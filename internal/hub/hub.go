package hub

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/logging"
	"github.com/pion/transport/v5"
	"github.com/pion/turn/v6"

	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/internal/ratelimit"
	"lighthouse-in-snoo/internal/stunserver"
	"lighthouse-in-snoo/internal/turnserver"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/protocol"
)

// Config configures the zero-config Lighthouse universal public hub and relay.
// The hub stores no static policy files or SQLite state; it owns the virtual IPv4 CIDR,
// assigns each registered peer an IP from that CIDR, and enforces automatic in-memory ACL
// based strictly on shared passphrase channels and active broadcast status.
type Config struct {
	HTTPSListenAddr string
	HTTPSListener   net.Listener // Optional pre-bound TCP listener (used in tests).
	TLSConfig       *tls.Config
	TLSCertFile     string
	TLSKeyFile      string
	AutoTLS         bool               // Auto-generate a self-signed TLS 1.3 cert when cert/key are omitted.
	TLSDir          string             // Optional directory to persist/reload auto-generated tls.crt and tls.key.
	TLSAlgorithm    identity.Algorithm // Key algorithm for auto-generated TLS cert (default ed25519).
	TLSRSABits      int                // Optional RSA modulus bits when TLSAlgorithm=rsa (default 3072).
	HubOrigin       string             // Canonical wss://host[:port] expected in registration proofs.
	VirtualCIDR     netip.Prefix       // Virtual IPv4 subnet assigned to peers (default 10.88.0.0/16).

	TCPOnly          bool           // Explicit opt-in to disable all UDP sockets and serve TLS 1.3/TCP only.
	AllowInsecure    bool           // Explicit opt-in required for plaintext STUN/TURN.
	EnableSTUN       bool           // Enable STUNS (DTLS 1.3/UDP default; TLS 1.3/TCP when TCPOnly).
	STUNSListenAddr  string         // Encrypted STUNS/TURNS listen address (default :5349).
	STUNSPacketConn  net.PacketConn // Optional pre-bound UDP PacketConn (prohibited when TCPOnly).
	STUNSTLSListener net.Listener   // Optional pre-bound TCP listener for TLS 1.3 STUNS/TURNS (TCPOnly).
	STUNListenAddr   string         // Plaintext STUN/TURN listen address (requires AllowInsecure).
	STUNPacketConn   net.PacketConn // Optional pre-bound plaintext UDP PacketConn (requires AllowInsecure).
	STUNTCPListener  net.Listener   // Optional pre-bound plaintext TCP listener (requires AllowInsecure and TCPOnly).

	EnableTURN         bool              // Enable universal TURNS relay (auto-mints credentials per registered peer).
	TURNSTLSListenAddr string            // Optional secondary TLS 1.3 TCP listen address for ?transport=tcp fallback.
	TURNRealm          string            // TURN authentication realm (default "lighthouse").
	TURNSecret         string            // Optional HMAC shared secret (auto-generated ephemerally when EnableTURN is true).
	TURNUsers          map[string]string // Optional static username -> password TURN credentials.
	TURNAuthHandler    turn.AuthHandler  // Optional custom TURN AuthHandler.
	TURNPublicIP       net.IP            // Optional advertised public relay IP for TURN allocations.
	TURNAdvertiseHost  string            // Optional hostname/IP advertised in RegisteredMessage.Relay URIs.
	TURNRelayBindAddr  string            // Local bind IP for TURN UDP relay sockets.
	TURNRelayMinPort   uint16
	TURNRelayMaxPort   uint16
	TURNNet            transport.Net
	PionLoggerFactory  logging.LoggerFactory

	PresenceHeartbeat   time.Duration
	PresenceTTL         time.Duration
	ChallengeTTL        time.Duration
	SignalingTTL        time.Duration
	MaxClockSkew        time.Duration
	MaxMessageBytes     int
	MaxCandidatesPerGen int
	MaxSessionsPerPeer  int
	MaxChannelsPerPeer  int
	MaxConnsPerIP       int
	MaxTotalConns       int
	PerIPConnRPS        float64
	PerIPConnBurst      int
	PerPeerMsgRPS       float64
	PerPeerMsgBurst     int
	MaxTrackedSessions  int
	STUNPerIPRPS        float64
	STUNPerIPBurst      int
	Logger              *slog.Logger
}

// Stats exposes aggregate non-sensitive control-plane and STUN counters.
type Stats struct {
	ActiveSessions      int
	ActiveChannels      int
	RegistrationsOK     uint64
	RegistrationsFailed uint64
	BroadcastsUpdated   uint64
	SignalsForwarded    uint64
	SignalsRejected     uint64
	AutoACLDenied       uint64
	RateLimited         uint64
	STUN                stunserver.Stats
}

type peerSession struct {
	id         uint64
	conn       *websocket.Conn
	remoteIP   string
	peerID     string
	publicKey  identity.PublicKey
	assignedIP netip.Addr
	expiresAt  atomic.Int64 // Unix nanos of presence lease expiry
	writeMu    sync.Mutex
	closed     atomic.Bool
	cancel     context.CancelFunc
	subscribed map[string]struct{} // guarded by hub.mu
	broadcasts map[string]struct{} // guarded by hub.mu
}

func (ps *peerSession) sendRaw(ctx context.Context, payload []byte) error {
	if ps.closed.Load() {
		return net.ErrClosed
	}
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()
	if ps.closed.Load() {
		return net.ErrClosed
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return ps.conn.Write(wctx, websocket.MessageText, payload)
}

func (ps *peerSession) sendJSON(ctx context.Context, msg any) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return ps.sendRaw(ctx, raw)
}

type senderGenState struct {
	nextSeq        uint64
	candidateCount int
}

type negotiationRecord struct {
	sessionID        string
	peerA            string
	peerB            string
	activeGeneration uint32
	closed           bool
	updatedAt        time.Time
	senderGens       map[string]*senderGenState
}

// Server is the zero-config Lighthouse control-plane and universal relay service.
// It owns virtual CIDR assignment and automatic passphrase/broadcast ACL, and never
// terminates peer-to-peer WebRTC DTLS 1.3 sessions.
type Server struct {
	cfg           Config
	hubOrigin     string
	virtualCIDR   netip.Prefix
	tlsAlgorithm  identity.Algorithm
	tlsPersisted  bool
	turnSecret    string
	stunSrv       *stunserver.Server
	turnSrv       *turnserver.Server
	httpSrv       *http.Server
	httpsListener net.Listener
	log           *slog.Logger

	ipConnRate  *ratelimit.KeyedLimiter
	ipConnConc  *ratelimit.ConcurrencyLimiter
	peerMsgRate *ratelimit.KeyedLimiter

	mu           sync.RWMutex
	nextSessSeq  uint64
	sessions     map[string][]*peerSession
	channels     map[string]map[string]protocol.BroadcastPeer // channelID -> peerID -> signed broadcast
	channelSubs  map[string]map[*peerSession]struct{}         // channelID -> subscribed sessions
	negotiations map[string]*negotiationRecord

	// Optional test hook strictly for negative security tests simulating a compromised hub.
	forwardHook func(raw []byte) []byte

	closed  atomic.Bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
	nowFunc func() time.Time

	regOK       atomic.Uint64
	regFailed   atomic.Uint64
	bcastCount  atomic.Uint64
	sigFwd      atomic.Uint64
	sigRejected atomic.Uint64
	aclDenied   atomic.Uint64
	rateDropped atomic.Uint64
}

// New creates and starts a zero-config Lighthouse Hub and optional universal STUNS/TURNS relay.
func New(cfgIn *Config) (*Server, error) {
	var cfg Config
	if cfgIn != nil {
		cfg = *cfgIn
	}
	applyDefaults(&cfg)
	var origin string
	if strings.TrimSpace(cfg.HubOrigin) != "" {
		var originErr error
		origin, originErr = identity.CanonicalizeOrigin(cfg.HubOrigin)
		if originErr != nil {
			return nil, fmt.Errorf("hub origin: %w", originErr)
		}
	}
	virtualCIDR := cfg.VirtualCIDR
	if !virtualCIDR.IsValid() {
		virtualCIDR = identity.DefaultVirtualCIDR()
	} else {
		var cidrErr error
		virtualCIDR, cidrErr = identity.ParseVirtualCIDR(virtualCIDR.String())
		if cidrErr != nil {
			return nil, fmt.Errorf("hub virtual cidr: %w", cidrErr)
		}
	}

	resolvedTLS, err := buildTLS13Config(&cfg, origin)
	if err != nil {
		return nil, err
	}
	tlsCfg := resolvedTLS.config

	rawLn := cfg.HTTPSListener
	if rawLn == nil {
		var listenErr error
		rawLn, listenErr = net.Listen("tcp", cfg.HTTPSListenAddr)
		if listenErr != nil {
			return nil, fmt.Errorf("listen https %s: %w", cfg.HTTPSListenAddr, listenErr)
		}
	}
	ln := newTLSOrProxyListener(rawLn, tlsCfg)

	if cfg.TCPOnly && (cfg.STUNSPacketConn != nil || cfg.STUNPacketConn != nil) {
		_ = ln.Close()
		return nil, errors.New("hub: UDP PacketConn is prohibited when TCPOnly=true")
	}

	wantsPlain := cfg.STUNListenAddr != "" || cfg.STUNPacketConn != nil || cfg.STUNTCPListener != nil
	if wantsPlain && !cfg.AllowInsecure {
		_ = ln.Close()
		return nil, stunserver.ErrInsecureSTUNProhibited
	}

	wantsTURN := cfg.EnableTURN || cfg.TURNSecret != "" || len(cfg.TURNUsers) > 0 || cfg.TURNAuthHandler != nil
	wantsSTUNS := cfg.STUNSListenAddr != "" || cfg.STUNSPacketConn != nil || cfg.STUNSTLSListener != nil
	if (cfg.EnableSTUN || wantsTURN) && !wantsSTUNS && !wantsPlain && cfg.TURNSTLSListenAddr == "" {
		cfg.STUNSListenAddr = stunserver.DefaultSTUNSAddr
		wantsSTUNS = true
	}

	turnSecret := strings.TrimSpace(cfg.TURNSecret)
	if wantsTURN && turnSecret == "" && len(cfg.TURNUsers) == 0 && cfg.TURNAuthHandler == nil {
		// Universal public relay: mint a fresh ephemeral HMAC secret automatically.
		var rawSecret [32]byte
		if _, rErr := rand.Read(rawSecret[:]); rErr != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("generate ephemeral turn secret: %w", rErr)
		}
		turnSecret = base64.RawURLEncoding.EncodeToString(rawSecret[:])
	}

	var (
		stunSrv *stunserver.Server
		turnSrv *turnserver.Server
	)
	if wantsTURN {
		turnCfg := turnserver.Config{
			TLSConfig:        tlsCfg,
			AllowInsecure:    cfg.AllowInsecure,
			TLSListenAddr:    cfg.TURNSTLSListenAddr,
			Realm:            cfg.TURNRealm,
			SharedSecret:     turnSecret,
			Users:            cfg.TURNUsers,
			AuthHandler:      cfg.TURNAuthHandler,
			PublicIP:         cfg.TURNPublicIP,
			RelayBindAddress: cfg.TURNRelayBindAddr,
			RelayMinPort:     cfg.TURNRelayMinPort,
			RelayMaxPort:     cfg.TURNRelayMaxPort,
			RelayNet:         cfg.TURNNet,
			LoggerFactory:    cfg.PionLoggerFactory,
		}
		if cfg.TCPOnly {
			if wantsSTUNS {
				if turnCfg.TLSListenAddr == "" {
					turnCfg.TLSListenAddr = cfg.STUNSListenAddr
				}
				turnCfg.TLSListener = cfg.STUNSTLSListener
			}
			if wantsPlain {
				turnCfg.TCPListenAddr = cfg.STUNListenAddr
				turnCfg.TCPListener = cfg.STUNTCPListener
			}
		} else {
			if wantsSTUNS {
				turnCfg.DTLSListenAddr = cfg.STUNSListenAddr
				turnCfg.DTLSPacketConn = cfg.STUNSPacketConn
			}
			if wantsPlain {
				turnCfg.UDPListenAddr = cfg.STUNListenAddr
				turnCfg.UDPPacketConn = cfg.STUNPacketConn
			}
		}
		turnSrv, err = turnserver.New(&turnCfg)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
	} else if wantsSTUNS || wantsPlain {
		stunCfg := stunserver.Config{
			AllowInsecure: cfg.AllowInsecure,
			PerIPRPS:      cfg.STUNPerIPRPS,
			PerIPBurst:    cfg.STUNPerIPBurst,
			LoggerFactory: cfg.PionLoggerFactory,
			Logger:        cfg.Logger,
		}
		if cfg.TCPOnly {
			if wantsSTUNS {
				stunCfg.TLSConfig = tlsCfg
				stunCfg.TLSListenAddr = cfg.STUNSListenAddr
				stunCfg.TLSListener = cfg.STUNSTLSListener
			}
			if wantsPlain {
				stunCfg.TCPListenAddr = cfg.STUNListenAddr
				stunCfg.TCPListener = cfg.STUNTCPListener
			}
		} else {
			if wantsSTUNS {
				stunCfg.TLSConfig = tlsCfg
				stunCfg.DTLSListenAddr = cfg.STUNSListenAddr
				stunCfg.DTLSPacketConn = cfg.STUNSPacketConn
			}
			if wantsPlain {
				stunCfg.ListenAddr = cfg.STUNListenAddr
				stunCfg.PacketConn = cfg.STUNPacketConn
			}
		}
		stunSrv, err = stunserver.New(&stunCfg)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
	}

	s := &Server{
		cfg:           cfg,
		hubOrigin:     origin,
		virtualCIDR:   virtualCIDR,
		tlsAlgorithm:  resolvedTLS.algorithm,
		tlsPersisted:  resolvedTLS.persisted,
		turnSecret:    turnSecret,
		stunSrv:       stunSrv,
		turnSrv:       turnSrv,
		httpsListener: ln,
		log:           cfg.Logger,
		ipConnRate:    ratelimit.NewKeyedLimiter(cfg.PerIPConnRPS, cfg.PerIPConnBurst, 8192, 5*time.Minute),
		ipConnConc:    ratelimit.NewConcurrencyLimiter(cfg.MaxConnsPerIP, cfg.MaxTotalConns),
		peerMsgRate:   ratelimit.NewKeyedLimiter(cfg.PerPeerMsgRPS, cfg.PerPeerMsgBurst, 8192, 5*time.Minute),
		sessions:      make(map[string][]*peerSession),
		channels:      make(map[string]map[string]protocol.BroadcastPeer),
		channelSubs:   make(map[string]map[*peerSession]struct{}),
		negotiations:  make(map[string]*negotiationRecord),
		stopCh:        make(chan struct{}),
		nowFunc:       time.Now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/signal", s.handleSignalWS)

	s.httpSrv = &http.Server{
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := s.httpSrv.Serve(s.httpsListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !s.closed.Load() {
			s.log.Error("https server stopped unexpectedly", "err", err)
		}
	}()
	go s.reapLoop()

	return s, nil
}

func applyDefaults(cfg *Config) {
	if cfg.HTTPSListenAddr == "" {
		cfg.HTTPSListenAddr = ":8443"
	}
	if cfg.PresenceHeartbeat <= 0 {
		cfg.PresenceHeartbeat = 20 * time.Second
	}
	if cfg.PresenceTTL <= 0 {
		cfg.PresenceTTL = 60 * time.Second
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = protocol.ChallengeTTL
	}
	if cfg.SignalingTTL <= 0 {
		cfg.SignalingTTL = protocol.DefaultSignalingTTL
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = protocol.DefaultMaxClockSkew
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = protocol.MaxSignalingMessageSize
	}
	if cfg.MaxCandidatesPerGen <= 0 {
		cfg.MaxCandidatesPerGen = protocol.DefaultMaxCandidatesPerGeneration
	}
	if cfg.MaxSessionsPerPeer <= 0 {
		cfg.MaxSessionsPerPeer = 2
	}
	if cfg.MaxChannelsPerPeer <= 0 {
		cfg.MaxChannelsPerPeer = 8
	}
	if cfg.MaxConnsPerIP <= 0 {
		cfg.MaxConnsPerIP = 32
	}
	if cfg.MaxTotalConns <= 0 {
		cfg.MaxTotalConns = 4096
	}
	if cfg.PerIPConnRPS <= 0 {
		cfg.PerIPConnRPS = 20
	}
	if cfg.PerIPConnBurst <= 0 {
		cfg.PerIPConnBurst = 40
	}
	if cfg.PerPeerMsgRPS <= 0 {
		cfg.PerPeerMsgRPS = 100
	}
	if cfg.PerPeerMsgBurst <= 0 {
		cfg.PerPeerMsgBurst = 200
	}
	if cfg.MaxTrackedSessions <= 0 {
		cfg.MaxTrackedSessions = 8192
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
}

// HTTPSAddr returns the bound TCP address of the HTTPS/WSS server.
func (s *Server) HTTPSAddr() net.Addr {
	return s.httpsListener.Addr()
}

// TCPOnly reports whether the hub is operating in TCP-only mode with UDP disabled.
func (s *Server) TCPOnly() bool {
	return s.cfg.TCPOnly
}

// TLSAlgorithm returns the key algorithm of the hub's active TLS 1.3 certificate.
func (s *Server) TLSAlgorithm() identity.Algorithm {
	return s.tlsAlgorithm
}

// TLSPersisted reports whether the hub's TLS certificate/key are persisted on disk.
func (s *Server) TLSPersisted() bool {
	return s.tlsPersisted
}

// STUNSDTLSAddr returns the bound DTLS 1.3 / UDP STUNS/TURNS address, or nil if disabled.
func (s *Server) STUNSDTLSAddr() net.Addr {
	if s.turnSrv != nil && s.turnSrv.DTLSAddr() != nil {
		return s.turnSrv.DTLSAddr()
	}
	if s.stunSrv != nil && s.stunSrv.DTLSAddr() != nil {
		return s.stunSrv.DTLSAddr()
	}
	return nil
}

// STUNSTLSAddr returns the bound TLS 1.3 / TCP STUNS/TURNS address, or nil if disabled.
func (s *Server) STUNSTLSAddr() net.Addr {
	if s.turnSrv != nil && s.turnSrv.TLSAddr() != nil {
		return s.turnSrv.TLSAddr()
	}
	if s.stunSrv != nil && s.stunSrv.TLSAddr() != nil {
		return s.stunSrv.TLSAddr()
	}
	return nil
}

// STUNSAddr returns the bound encrypted STUNS/TURNS address (DTLS/UDP default, or TLS/TCP in TCP-only mode).
func (s *Server) STUNSAddr() net.Addr {
	if a := s.STUNSDTLSAddr(); a != nil {
		return a
	}
	return s.STUNSTLSAddr()
}

// TURNSTLSAddr returns the TLS 1.3 / TCP TURNS address, or nil if disabled.
func (s *Server) TURNSTLSAddr() net.Addr {
	if s.turnSrv != nil {
		return s.turnSrv.TLSAddr()
	}
	return nil
}

// STUNUDPAddr returns the bound opt-in plaintext UDP STUN/TURN address, or nil if disabled.
func (s *Server) STUNUDPAddr() net.Addr {
	if s.turnSrv != nil && s.turnSrv.UDPAddr() != nil {
		return s.turnSrv.UDPAddr()
	}
	if s.stunSrv != nil && s.stunSrv.UDPAddr() != nil {
		return s.stunSrv.UDPAddr()
	}
	return nil
}

// STUNTCPAddr returns the bound opt-in plaintext TCP STUN/TURN address, or nil if disabled.
func (s *Server) STUNTCPAddr() net.Addr {
	if s.turnSrv != nil && s.turnSrv.TCPAddr() != nil {
		return s.turnSrv.TCPAddr()
	}
	if s.stunSrv != nil && s.stunSrv.TCPAddr() != nil {
		return s.stunSrv.TCPAddr()
	}
	return nil
}

// STUNAddr returns the primary STUNS/TURNS encrypted address when active, otherwise the plaintext address.
func (s *Server) STUNAddr() net.Addr {
	if a := s.STUNSAddr(); a != nil {
		return a
	}
	if a := s.STUNUDPAddr(); a != nil {
		return a
	}
	return s.STUNTCPAddr()
}

// TURNActive reports whether the integrated universal TURNS/TURN relay service is running.
func (s *Server) TURNActive() bool {
	return s.turnSrv != nil
}

// HubOrigin returns the canonical WSS origin configured for registration proofs.
func (s *Server) HubOrigin() string {
	return s.hubOrigin
}

// VirtualCIDR returns the hub's configured IPv4 virtual subnet assigned to registered peers.
func (s *Server) VirtualCIDR() netip.Prefix {
	return s.virtualCIDR
}

// SetForwardTamperHookForTesting installs a raw frame mutator strictly for negative security tests.
func (s *Server) SetForwardTamperHookForTesting(hook func(raw []byte) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwardHook = hook
}

// Stats returns aggregate non-sensitive operational statistics.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	active := 0
	for _, list := range s.sessions {
		active += len(list)
	}
	rooms := make(map[string]struct{}, len(s.channels)+len(s.channelSubs))
	for chID, members := range s.channels {
		if len(members) > 0 {
			rooms[chID] = struct{}{}
		}
	}
	for chID, subs := range s.channelSubs {
		if len(subs) > 0 {
			rooms[chID] = struct{}{}
		}
	}
	activeChannels := len(rooms)
	s.mu.RUnlock()

	var stunStats stunserver.Stats
	if s.stunSrv != nil {
		stunStats = s.stunSrv.Stats()
	}
	return Stats{
		ActiveSessions:      active,
		ActiveChannels:      activeChannels,
		RegistrationsOK:     s.regOK.Load(),
		RegistrationsFailed: s.regFailed.Load(),
		BroadcastsUpdated:   s.bcastCount.Load(),
		SignalsForwarded:    s.sigFwd.Load(),
		SignalsRejected:     s.sigRejected.Load(),
		AutoACLDenied:       s.aclDenied.Load(),
		RateLimited:         s.rateDropped.Load(),
		STUN:                stunStats,
	}
}

// Close shuts down the HTTPS/WSS signaling server, active WebSockets, and STUNS/TURNS servers.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.stopCh)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.httpSrv.Shutdown(ctx)
	_ = s.httpsListener.Close()

	s.mu.Lock()
	for pid, list := range s.sessions {
		for _, ps := range list {
			ps.closed.Store(true)
			ps.cancel()
			_ = ps.conn.Close(websocket.StatusGoingAway, "server_shutdown")
		}
		delete(s.sessions, pid)
	}
	s.channels = make(map[string]map[string]protocol.BroadcastPeer)
	s.channelSubs = make(map[string]map[*peerSession]struct{})
	s.mu.Unlock()

	var stunErr error
	if s.stunSrv != nil {
		stunErr = s.stunSrv.Close()
	}
	var turnErr error
	if s.turnSrv != nil {
		turnErr = s.turnSrv.Close()
	}
	s.wg.Wait()
	return errors.Join(stunErr, turnErr)
}

func (s *Server) buildRelayInfoForPeer(peerID, reqOrigin string) *protocol.RelayInfo {
	if s.turnSrv == nil || s.turnSecret == "" {
		return nil
	}
	var uris []string
	if dtlsAddr := s.turnSrv.DTLSAddr(); dtlsAddr != nil {
		uris = append(uris, "turns:"+s.formatAdvertisedAddr(dtlsAddr, reqOrigin))
	}
	if tlsAddr := s.turnSrv.TLSAddr(); tlsAddr != nil {
		uris = append(uris, "turns:"+s.formatAdvertisedAddr(tlsAddr, reqOrigin)+"?transport=tcp")
	}
	if len(uris) == 0 {
		return nil
	}
	const ttl = 12 * time.Hour
	user, pass, err := turnserver.GenerateCredentials(s.turnSecret, peerID, ttl)
	if err != nil {
		return nil
	}
	return &protocol.RelayInfo{
		URIs:       uris,
		Username:   user,
		Credential: pass,
		ExpiresAt:  s.nowFunc().Add(ttl).Unix(),
	}
}

func (s *Server) formatAdvertisedAddr(addr net.Addr, reqOrigin string) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	if s.cfg.TURNAdvertiseHost != "" {
		return net.JoinHostPort(s.cfg.TURNAdvertiseHost, port)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		if s.cfg.TURNPublicIP != nil {
			return net.JoinHostPort(s.cfg.TURNPublicIP.String(), port)
		}
		originForHost := s.hubOrigin
		if originForHost == "" {
			originForHost = reqOrigin
		}
		if u, uErr := url.Parse(originForHost); uErr == nil && u.Hostname() != "" {
			return net.JoinHostPort(u.Hostname(), port)
		}
	}
	return net.JoinHostPort(host, port)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}

func (s *Server) handleSignalWS(w http.ResponseWriter, r *http.Request) {
	remoteIP := extractClientIP(r)
	if !s.ipConnRate.Allow(remoteIP) || !s.ipConnConc.Acquire(remoteIP) {
		s.rateDropped.Add(1)
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	defer s.ipConnConc.Release(remoteIP)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(int64(s.cfg.MaxMessageBytes))

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	challenge, err := protocol.NewChallenge()
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "internal_error")
		return
	}
	now := s.nowFunc()
	challengeExp := now.Add(s.cfg.ChallengeTTL)

	reqOrigin := s.resolveRequestOrigin(r)

	chalRaw, err := json.Marshal(protocol.ChallengeMessage{
		V:         protocol.Version,
		Type:      protocol.TypeChallenge,
		Challenge: challenge,
		HubOrigin: reqOrigin,
		ExpiresAt: challengeExp.Unix(),
	})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "internal_error")
		return
	}
	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	err = conn.Write(wctx, websocket.MessageText, chalRaw)
	wcancel()
	if err != nil {
		_ = conn.Close(websocket.StatusProtocolError, "write_failed")
		return
	}

	regCtx, regCancel := context.WithTimeout(ctx, s.cfg.ChallengeTTL)
	msgType, rawReg, err := conn.Read(regCtx)
	regCancel()
	if err != nil {
		if errors.Is(err, websocket.ErrMessageTooBig) {
			s.rateDropped.Add(1)
			_ = conn.Close(websocket.StatusMessageTooBig, protocol.ErrCodeMessageTooLarge)
			return
		}
		_ = conn.Close(websocket.StatusPolicyViolation, protocol.ErrCodeChallengeInvalid)
		return
	}
	if msgType != websocket.MessageText {
		s.regFailed.Add(1)
		s.writeErrorDirect(ctx, conn, protocol.ErrCodeMalformedMessage, "binary frames prohibited", "")
		_ = conn.Close(websocket.StatusUnsupportedData, protocol.ErrCodeMalformedMessage)
		return
	}

	ps, errCode, errDetail := s.authenticateRegistration(conn, cancel, remoteIP, reqOrigin, challenge, challengeExp, rawReg)
	if ps == nil {
		s.regFailed.Add(1)
		s.log.Warn("peer registration rejected", "remote_ip", remoteIP, "code", errCode)
		s.writeErrorDirect(ctx, conn, errCode, errDetail, "")
		_ = conn.Close(websocket.StatusPolicyViolation, errCode)
		return
	}
	defer s.unregisterSession(ps)

	s.regOK.Add(1)
	s.log.Info("peer registered", "peer_id", ps.peerID)

	hbSec := max(1, int(s.cfg.PresenceHeartbeat/time.Second))
	if err := ps.sendJSON(ctx, protocol.RegisteredMessage{
		V:                    protocol.Version,
		Type:                 protocol.TypeRegistered,
		PeerID:               ps.peerID,
		ExpiresAt:            time.Unix(0, ps.expiresAt.Load()).Unix(),
		HeartbeatIntervalSec: hbSec,
		VirtualCIDR:          s.virtualCIDR.String(),
		AssignedIP:           ps.assignedIP.String(),
		Relay:                s.buildRelayInfoForPeer(ps.peerID, reqOrigin),
	}); err != nil {
		return
	}

	for !ps.closed.Load() && !s.closed.Load() {
		mType, raw, readErr := conn.Read(ctx)
		if readErr != nil {
			if errors.Is(readErr, websocket.ErrMessageTooBig) {
				s.rateDropped.Add(1)
				s.sigRejected.Add(1)
				_ = conn.Close(websocket.StatusMessageTooBig, protocol.ErrCodeMessageTooLarge)
			}
			return
		}
		if mType != websocket.MessageText {
			s.sigRejected.Add(1)
			_ = ps.sendJSON(ctx, protocol.ErrorMessage{
				V:      protocol.Version,
				Type:   protocol.TypeError,
				Code:   protocol.ErrCodeMalformedMessage,
				Detail: "binary frames prohibited",
			})
			_ = conn.Close(websocket.StatusUnsupportedData, protocol.ErrCodeMalformedMessage)
			return
		}
		if !s.peerMsgRate.Allow(ps.peerID) {
			s.rateDropped.Add(1)
			_ = ps.sendJSON(ctx, protocol.ErrorMessage{
				V:    protocol.Version,
				Type: protocol.TypeError,
				Code: protocol.ErrCodeRateLimited,
			})
			continue
		}
		if s.nowFunc().UnixNano() > ps.expiresAt.Load() {
			_ = conn.Close(websocket.StatusPolicyViolation, "presence_expired")
			return
		}
		s.handleAuthenticatedMessage(ctx, ps, raw)
	}
}

func (s *Server) authenticateRegistration(
	conn *websocket.Conn,
	cancel context.CancelFunc,
	remoteIP, expectedOrigin, expectedChallenge string,
	challengeExp time.Time,
	raw []byte,
) (sess *peerSession, errCode, errDetail string) {
	hdr, err := protocol.PeekHeader(raw, s.cfg.MaxMessageBytes)
	if err != nil {
		return nil, classifyHeaderErr(err), "invalid message header"
	}
	if hdr.Type != protocol.TypeRegister {
		return nil, protocol.ErrCodeUnauthenticated, "must register first"
	}

	var reg protocol.RegisterMessage
	if err := jcs.UnmarshalStrict(raw, &reg); err != nil {
		return nil, protocol.ErrCodeMalformedMessage, "invalid register payload"
	}
	now := s.nowFunc()
	if now.After(challengeExp) || reg.Challenge == "" || reg.Challenge != expectedChallenge {
		return nil, protocol.ErrCodeChallengeInvalid, "invalid or expired challenge"
	}
	canonOrigin, err := identity.CanonicalizeOrigin(reg.HubOrigin)
	if err != nil || canonOrigin != expectedOrigin {
		return nil, protocol.ErrCodeAuthFailed, "hub_origin mismatch"
	}
	pub, err := identity.DecodePublicKey(reg.PublicKey)
	if err != nil {
		return nil, protocol.ErrCodeAuthFailed, "invalid public_key"
	}
	if err := identity.VerifyRegistrationChallenge(pub, reg.PeerID, expectedChallenge, expectedOrigin, reg.Proof); err != nil {
		return nil, protocol.ErrCodeAuthFailed, "invalid challenge proof"
	}

	assignedIP, err := identity.VirtualIPv4InPrefix(reg.PeerID, s.virtualCIDR)
	if err != nil {
		return nil, protocol.ErrCodeAuthFailed, "failed to assign virtual IP"
	}

	ps := &peerSession{
		conn:       conn,
		remoteIP:   remoteIP,
		peerID:     reg.PeerID,
		publicKey:  pub,
		assignedIP: assignedIP,
		cancel:     cancel,
		subscribed: make(map[string]struct{}),
		broadcasts: make(map[string]struct{}),
	}
	ps.expiresAt.Store(now.Add(s.cfg.PresenceTTL).UnixNano())

	s.mu.Lock()
	existing := s.sessions[ps.peerID]
	active := existing[:0]
	for _, old := range existing {
		if !old.closed.Load() && now.UnixNano() <= old.expiresAt.Load() {
			active = append(active, old)
		}
	}
	if len(active) >= s.cfg.MaxSessionsPerPeer {
		s.mu.Unlock()
		return nil, protocol.ErrCodeSessionLimit, "concurrent session limit exceeded"
	}
	s.nextSessSeq++
	ps.id = s.nextSessSeq
	s.sessions[ps.peerID] = append(active, ps)
	s.mu.Unlock()

	return ps, "", ""
}

func (s *Server) unregisterSession(ps *peerSession) {
	ps.closed.Store(true)
	ps.cancel()

	var affectedChannels []string
	s.mu.Lock()
	list := s.sessions[ps.peerID]
	kept := list[:0]
	for _, item := range list {
		if item.id != ps.id {
			kept = append(kept, item)
		}
	}
	if len(kept) == 0 {
		delete(s.sessions, ps.peerID)
	} else {
		s.sessions[ps.peerID] = kept
	}

	for chID := range ps.subscribed {
		if subs, ok := s.channelSubs[chID]; ok {
			delete(subs, ps)
			if len(subs) == 0 {
				delete(s.channelSubs, chID)
			}
		}
	}
	for chID := range ps.broadcasts {
		if members, ok := s.channels[chID]; ok {
			delete(members, ps.peerID)
			if len(members) == 0 {
				delete(s.channels, chID)
			}
			affectedChannels = append(affectedChannels, chID)
		}
	}
	s.mu.Unlock()

	for _, chID := range affectedChannels {
		s.notifyChannelSubscribers(chID)
	}
	_ = ps.conn.Close(websocket.StatusNormalClosure, "closed")
}

func (s *Server) handleAuthenticatedMessage(ctx context.Context, ps *peerSession, raw []byte) {
	hdr, err := protocol.PeekHeader(raw, s.cfg.MaxMessageBytes)
	if err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: classifyHeaderErr(err),
		})
		return
	}

	switch hdr.Type {
	case protocol.TypeHeartbeat:
		var hb protocol.HeartbeatMessage
		if err := jcs.UnmarshalStrict(raw, &hb); err != nil {
			s.sigRejected.Add(1)
			_ = ps.sendJSON(ctx, protocol.ErrorMessage{
				V:    protocol.Version,
				Type: protocol.TypeError,
				Code: protocol.ErrCodeMalformedMessage,
			})
			return
		}
		ps.expiresAt.Store(s.nowFunc().Add(s.cfg.PresenceTTL).UnixNano())

	case protocol.TypeChannelJoin:
		s.handleChannelJoin(ctx, ps, raw)

	case protocol.TypeChannelLeave:
		s.handleChannelLeave(ctx, ps, raw)

	case protocol.TypeBroadcast:
		s.handleBroadcast(ctx, ps, raw)

	case protocol.TypeOffer, protocol.TypeAnswer, protocol.TypeCandidate, protocol.TypeEndOfCandidates, protocol.TypeClose:
		s.handlePeerSignal(ctx, ps, raw)

	default:
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
	}
}

func (s *Server) handleChannelJoin(ctx context.Context, ps *peerSession, raw []byte) {
	var msg protocol.ChannelJoinMessage
	if err := jcs.UnmarshalStrict(raw, &msg); err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
		return
	}
	if err := identity.ValidateChannelID(msg.ChannelID); err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
		return
	}

	s.mu.Lock()
	if _, exists := ps.subscribed[msg.ChannelID]; !exists && len(ps.subscribed) >= s.cfg.MaxChannelsPerPeer {
		s.mu.Unlock()
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeRateLimited,
		})
		return
	}
	ps.subscribed[msg.ChannelID] = struct{}{}
	subs, ok := s.channelSubs[msg.ChannelID]
	if !ok {
		subs = make(map[*peerSession]struct{})
		s.channelSubs[msg.ChannelID] = subs
	}
	subs[ps] = struct{}{}
	peers := s.snapshotChannelPeersLocked(msg.ChannelID)
	s.mu.Unlock()

	_ = ps.sendJSON(ctx, protocol.ChannelPeersMessage{
		V:         protocol.Version,
		Type:      protocol.TypeChannelPeers,
		ChannelID: msg.ChannelID,
		Peers:     peers,
	})
}

func (s *Server) handleChannelLeave(ctx context.Context, ps *peerSession, raw []byte) {
	var msg protocol.ChannelLeaveMessage
	if err := jcs.UnmarshalStrict(raw, &msg); err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
		return
	}
	if err := identity.ValidateChannelID(msg.ChannelID); err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
		return
	}

	removedBroadcast := false
	s.mu.Lock()
	delete(ps.subscribed, msg.ChannelID)
	if subs, ok := s.channelSubs[msg.ChannelID]; ok {
		delete(subs, ps)
		if len(subs) == 0 {
			delete(s.channelSubs, msg.ChannelID)
		}
	}
	if _, wasBroadcasting := ps.broadcasts[msg.ChannelID]; wasBroadcasting {
		delete(ps.broadcasts, msg.ChannelID)
		if members, ok := s.channels[msg.ChannelID]; ok {
			delete(members, ps.peerID)
			if len(members) == 0 {
				delete(s.channels, msg.ChannelID)
			}
			removedBroadcast = true
		}
	}
	s.mu.Unlock()

	if removedBroadcast {
		s.notifyChannelSubscribers(msg.ChannelID)
	}
}

func (s *Server) handleBroadcast(ctx context.Context, ps *peerSession, raw []byte) {
	var msg protocol.BroadcastMessage
	if err := jcs.UnmarshalStrict(raw, &msg); err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
		return
	}
	if msg.PeerID != ps.peerID {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeSenderMismatch,
		})
		return
	}
	pub, err := protocol.VerifyBroadcast(&msg)
	if err != nil || !pub.Equal(ps.publicKey) {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeInvalidSignature,
		})
		return
	}

	s.mu.Lock()
	if msg.Active {
		if _, exists := ps.broadcasts[msg.ChannelID]; !exists && len(ps.broadcasts) >= s.cfg.MaxChannelsPerPeer {
			s.mu.Unlock()
			s.sigRejected.Add(1)
			_ = ps.sendJSON(ctx, protocol.ErrorMessage{
				V:    protocol.Version,
				Type: protocol.TypeError,
				Code: protocol.ErrCodeRateLimited,
			})
			return
		}
		ps.broadcasts[msg.ChannelID] = struct{}{}
		members, ok := s.channels[msg.ChannelID]
		if !ok {
			members = make(map[string]protocol.BroadcastPeer)
			s.channels[msg.ChannelID] = members
		}
		members[ps.peerID] = protocol.BroadcastPeer{
			PeerID:     msg.PeerID,
			PublicKey:  msg.PublicKey,
			SealedMeta: msg.SealedMeta,
			Timestamp:  msg.Timestamp,
			Sig:        msg.Sig,
		}
	} else {
		delete(ps.broadcasts, msg.ChannelID)
		if members, ok := s.channels[msg.ChannelID]; ok {
			delete(members, ps.peerID)
			if len(members) == 0 {
				delete(s.channels, msg.ChannelID)
			}
		}
	}
	s.mu.Unlock()

	s.bcastCount.Add(1)
	s.notifyChannelSubscribers(msg.ChannelID)
}

func (s *Server) snapshotChannelPeersLocked(channelID string) []protocol.BroadcastPeer {
	members := s.channels[channelID]
	out := make([]protocol.BroadcastPeer, 0, len(members))
	for _, bp := range members {
		out = append(out, bp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

func (s *Server) notifyChannelSubscribers(channelID string) {
	s.mu.RLock()
	subsMap := s.channelSubs[channelID]
	if len(subsMap) == 0 {
		s.mu.RUnlock()
		return
	}
	subs := make([]*peerSession, 0, len(subsMap))
	for sub := range subsMap {
		if !sub.closed.Load() {
			subs = append(subs, sub)
		}
	}
	peers := s.snapshotChannelPeersLocked(channelID)
	s.mu.RUnlock()

	payload, err := json.Marshal(protocol.ChannelPeersMessage{
		V:         protocol.Version,
		Type:      protocol.TypeChannelPeers,
		ChannelID: channelID,
		Peers:     peers,
	})
	if err != nil {
		return
	}
	ctx := context.Background()
	for _, sub := range subs {
		_ = sub.sendRaw(ctx, payload)
	}
}

func (s *Server) handlePeerSignal(ctx context.Context, ps *peerSession, raw []byte) {
	env, err := protocol.ParseUnsignedEnvelope(raw, s.cfg.MaxMessageBytes)
	if err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: classifyHeaderErr(err),
		})
		return
	}

	if env.From != ps.peerID {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      protocol.ErrCodeSenderMismatch,
			SessionID: env.SessionID,
		})
		return
	}

	now := s.nowFunc()
	if err := protocol.VerifyEnvelopeSignature(env, ps.publicKey, now, s.cfg.SignalingTTL, s.cfg.MaxClockSkew); err != nil {
		s.sigRejected.Add(1)
		code := protocol.ErrCodeInvalidSignature
		if errors.Is(err, protocol.ErrExpiredEnvelope) {
			code = protocol.ErrCodeExpiredMessage
		}
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      code,
			SessionID: env.SessionID,
		})
		return
	}

	if errCode, errDetail := s.validateAndRecordSequence(env, now); errCode != "" {
		s.sigRejected.Add(1)
		if errCode == protocol.ErrCodeNotAuthorized {
			s.aclDenied.Add(1)
		}
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      errCode,
			Detail:    errDetail,
			SessionID: env.SessionID,
		})
		return
	}

	recipients := s.onlineSessions(env.To)
	if len(recipients) == 0 {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      protocol.ErrCodePeerOffline,
			SessionID: env.SessionID,
		})
		return
	}

	outBytes := raw
	s.mu.RLock()
	hook := s.forwardHook
	s.mu.RUnlock()
	if hook != nil {
		outBytes = hook(append([]byte(nil), raw...))
	}

	delivered := false
	for _, dst := range recipients {
		if err := dst.sendRaw(ctx, outBytes); err == nil {
			delivered = true
		}
	}
	if env.Type == protocol.TypeClose {
		s.markNegotiationClosed(env.SessionID)
	}
	if !delivered {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      protocol.ErrCodePeerOffline,
			SessionID: env.SessionID,
		})
		return
	}
	s.sigFwd.Add(1)
}

func (s *Server) validateAndRecordSequence(env *protocol.SignalEnvelope, now time.Time) (errCode, errDetail string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, exists := s.negotiations[env.SessionID]
	if !exists {
		if env.Seq != 0 {
			return protocol.ErrCodeReplayedSignaling, "initial signaling sequence must be 0"
		}
		// Automatic server-side ACL: initiating a new session requires the target peer
		// to be actively broadcasting on a passphrase channel joined/broadcasted by the caller.
		if !s.autoACLAllowsLocked(env.From, env.To) {
			return protocol.ErrCodeNotAuthorized, "target peer is not broadcasting on a shared passphrase channel"
		}
		if len(s.negotiations) >= s.cfg.MaxTrackedSessions {
			s.evictOldestNegotiationLocked(now)
		}
		rec = &negotiationRecord{
			sessionID:        env.SessionID,
			peerA:            env.From,
			peerB:            env.To,
			activeGeneration: env.Generation,
			updatedAt:        now,
			senderGens:       make(map[string]*senderGenState),
		}
		s.negotiations[env.SessionID] = rec
	} else {
		validPair := (rec.peerA == env.From && rec.peerB == env.To) || (rec.peerA == env.To && rec.peerB == env.From)
		if !validPair || rec.closed {
			return protocol.ErrCodeReplayedSignaling, "replayed or closed signaling session"
		}
		if env.Generation < rec.activeGeneration {
			return protocol.ErrCodeStaleGeneration, "stale signaling generation"
		}
		if env.Generation > rec.activeGeneration {
			if env.Type != protocol.TypeOffer || env.Seq != 0 {
				return protocol.ErrCodeStaleGeneration, "generation advance requires offer seq 0"
			}
			rec.activeGeneration = env.Generation
		}
	}

	genKey := fmt.Sprintf("%s:%d", env.From, env.Generation)
	sg, ok := rec.senderGens[genKey]
	if !ok {
		sg = &senderGenState{}
		rec.senderGens[genKey] = sg
	}
	if env.Seq != sg.nextSeq {
		return protocol.ErrCodeReplayedSignaling, "out-of-sequence or replayed signaling envelope"
	}
	if env.Type == protocol.TypeCandidate {
		if sg.candidateCount >= s.cfg.MaxCandidatesPerGen {
			return protocol.ErrCodeCandidateLimit, "candidate limit exceeded"
		}
		sg.candidateCount++
	}
	sg.nextSeq = env.Seq + 1
	rec.updatedAt = now
	return "", ""
}

// autoACLAllowsLocked enforces automatic hub-side ACL derived strictly from live passphrase
// channel membership and target broadcast status: fromPeerID may initiate a new session to
// toPeerID iff toPeerID is actively broadcasting on at least one channel that fromPeerID
// has joined or is also broadcasting on.
func (s *Server) autoACLAllowsLocked(fromPeerID, toPeerID string) bool {
	fromSessions := s.sessions[fromPeerID]
	if len(fromSessions) == 0 {
		return false
	}
	nowNano := s.nowFunc().UnixNano()
	for chID, broadcasters := range s.channels {
		if _, targetBroadcasting := broadcasters[toPeerID]; !targetBroadcasting {
			continue
		}
		for _, fs := range fromSessions {
			if fs.closed.Load() || nowNano > fs.expiresAt.Load() {
				continue
			}
			if _, sub := fs.subscribed[chID]; sub {
				return true
			}
			if _, bcast := fs.broadcasts[chID]; bcast {
				return true
			}
		}
	}
	return false
}

func (s *Server) markNegotiationClosed(sessionID string) {
	s.mu.Lock()
	if rec, ok := s.negotiations[sessionID]; ok {
		rec.closed = true
	}
	s.mu.Unlock()
}

func (s *Server) evictOldestNegotiationLocked(now time.Time) {
	ttl := s.cfg.SignalingTTL + 2*s.cfg.MaxClockSkew + time.Minute
	var oldestID string
	var oldestTime time.Time
	for id, rec := range s.negotiations {
		if now.Sub(rec.updatedAt) > ttl {
			delete(s.negotiations, id)
			continue
		}
		if oldestID == "" || rec.updatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = rec.updatedAt
		}
	}
	if len(s.negotiations) >= s.cfg.MaxTrackedSessions && oldestID != "" {
		delete(s.negotiations, oldestID)
	}
}

func (s *Server) onlineSessions(peerID string) []*peerSession {
	nowNano := s.nowFunc().UnixNano()
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := s.sessions[peerID]
	var out []*peerSession
	for _, ps := range list {
		if !ps.closed.Load() && nowNano <= ps.expiresAt.Load() {
			out = append(out, ps)
		}
	}
	return out
}

func (s *Server) reapLoop() {
	defer s.wg.Done()
	interval := min(5*time.Second, max(50*time.Millisecond, s.cfg.PresenceTTL/2))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.reapExpired()
		}
	}
}

func (s *Server) reapExpired() {
	now := s.nowFunc()
	nowNano := now.UnixNano()
	negTTL := s.cfg.SignalingTTL + 2*s.cfg.MaxClockSkew + time.Minute

	var expired []*peerSession
	s.mu.Lock()
	for pid, list := range s.sessions {
		kept := list[:0]
		for _, ps := range list {
			if ps.closed.Load() || nowNano > ps.expiresAt.Load() {
				expired = append(expired, ps)
				continue
			}
			kept = append(kept, ps)
		}
		if len(kept) == 0 {
			delete(s.sessions, pid)
		} else {
			s.sessions[pid] = kept
		}
	}
	for sid, rec := range s.negotiations {
		if now.Sub(rec.updatedAt) > negTTL {
			delete(s.negotiations, sid)
		}
	}
	s.mu.Unlock()

	for _, ps := range expired {
		s.unregisterSession(ps)
	}

	// Ensure any empty or orphaned passphrase rooms are removed once zero live peers remain.
	var prunedBroadcastRooms []string
	s.mu.Lock()
	for chID, subs := range s.channelSubs {
		for sub := range subs {
			if sub.closed.Load() || nowNano > sub.expiresAt.Load() {
				delete(subs, sub)
			}
		}
		if len(subs) == 0 {
			delete(s.channelSubs, chID)
		}
	}
	for chID, members := range s.channels {
		removed := false
		for pid := range members {
			if len(s.sessions[pid]) == 0 {
				delete(members, pid)
				removed = true
			}
		}
		if len(members) == 0 {
			delete(s.channels, chID)
		}
		if removed {
			prunedBroadcastRooms = append(prunedBroadcastRooms, chID)
		}
	}
	s.mu.Unlock()

	for _, chID := range prunedBroadcastRooms {
		s.notifyChannelSubscribers(chID)
	}
}

func (s *Server) writeErrorDirect(ctx context.Context, conn *websocket.Conn, code, detail, sessionID string) {
	raw, err := json.Marshal(protocol.ErrorMessage{
		V:         protocol.Version,
		Type:      protocol.TypeError,
		Code:      code,
		Detail:    detail,
		SessionID: sessionID,
	})
	if err != nil {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = conn.Write(wctx, websocket.MessageText, raw)
}

func classifyHeaderErr(err error) string {
	switch {
	case errors.Is(err, protocol.ErrMessageTooLarge):
		return protocol.ErrCodeMessageTooLarge
	case errors.Is(err, protocol.ErrUnsupportedVer):
		return protocol.ErrCodeUnsupportedVersion
	case errors.Is(err, protocol.ErrUnknownType):
		return protocol.ErrCodeUnknownType
	default:
		return protocol.ErrCodeMalformedMessage
	}
}

func extractRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
