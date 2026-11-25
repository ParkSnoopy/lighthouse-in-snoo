package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/internal/ratelimit"
	"lighthouse-in-snoo/internal/store"
	"lighthouse-in-snoo/internal/stunserver"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/protocol"
)

// Config configures the Lighthouse control-plane hub and integrated STUN service.
type Config struct {
	HTTPSListenAddr string
	HTTPSListener   net.Listener // Optional pre-bound TCP listener (used in tests).
	TLSConfig       *tls.Config
	TLSCertFile     string
	TLSKeyFile      string
	HubOrigin       string // Canonical wss://host[:port] expected in registration proofs.

	EnableSTUN     bool
	STUNListenAddr string
	STUNPacketConn net.PacketConn // Optional pre-bound UDP PacketConn (e.g. vnet or test socket).

	Policy              identity.PolicyConfig
	SQLitePath          string
	PresenceHeartbeat   time.Duration
	PresenceTTL         time.Duration
	ChallengeTTL        time.Duration
	SignalingTTL        time.Duration
	MaxClockSkew        time.Duration
	MaxMessageBytes     int
	MaxCandidatesPerGen int
	MaxSessionsPerPeer  int
	MaxConnsPerIP       int
	MaxTotalConns       int
	PerIPConnRPS        float64
	PerIPConnBurst      int
	PerPeerMsgRPS       float64
	PerPeerMsgBurst     int
	PerPeerLookupRPS    float64
	PerPeerLookupBurst  int
	MaxTrackedSessions  int
	STUNPerIPRPS        float64
	STUNPerIPBurst      int
	Logger              *slog.Logger
}

// Stats exposes aggregate non-sensitive control-plane and STUN counters (Section 9).
type Stats struct {
	ActiveSessions      int
	RegistrationsOK     uint64
	RegistrationsFailed uint64
	LookupsOK           uint64
	LookupsDenied       uint64
	SignalsForwarded    uint64
	SignalsRejected     uint64
	RateLimited         uint64
	STUN                stunserver.Stats
}

type peerSession struct {
	id         uint64
	conn       *websocket.Conn
	remoteIP   string
	peerID     string
	publicKey  ed25519.PublicKey
	membership *identity.MembershipRecord
	expiresAt  atomic.Int64 // Unix nanos of presence lease expiry
	writeMu    sync.Mutex
	closed     atomic.Bool
	cancel     context.CancelFunc
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
	senderGens       map[string]*senderGenState // key: senderPeerID + ":" + gen
}

// Server is the single-container Lighthouse control-plane service (HTTPS/WSS + STUN).
// It intentionally has zero dependency on pion/webrtc or pion/turn (Section 2.1).
type Server struct {
	cfg           Config
	hubOrigin     string
	trust         *identity.TrustVerifier
	sqlStore      *store.Store
	stunSrv       *stunserver.Server
	httpSrv       *http.Server
	httpsListener net.Listener
	log           *slog.Logger

	ipConnRate   *ratelimit.KeyedLimiter
	ipConnConc   *ratelimit.ConcurrencyLimiter
	peerMsgRate  *ratelimit.KeyedLimiter
	peerLookRate *ratelimit.KeyedLimiter

	mu           sync.RWMutex
	nextSessSeq  uint64
	sessions     map[string][]*peerSession // peerID -> active sessions (bounded by MaxSessionsPerPeer)
	negotiations map[string]*negotiationRecord

	// Optional test/interceptor hook strictly for negative security test T06
	// (simulating a compromised hub tampering with forwarded frames). Nil in production.
	forwardHook func(raw []byte) []byte

	closed  atomic.Bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
	nowFunc func() time.Time

	regOK       atomic.Uint64
	regFailed   atomic.Uint64
	lookOK      atomic.Uint64
	lookDenied  atomic.Uint64
	sigFwd      atomic.Uint64
	sigRejected atomic.Uint64
	rateDropped atomic.Uint64
}

// New creates and starts a Lighthouse Hub server.
func New(cfg Config) (*Server, error) {
	applyDefaults(&cfg)
	origin, err := identity.CanonicalizeOrigin(cfg.HubOrigin)
	if err != nil {
		return nil, fmt.Errorf("hub origin: %w", err)
	}

	var sqlStore *store.Store
	policy := cfg.Policy
	if cfg.SQLitePath != "" {
		sqlStore, err = store.Open(cfg.SQLitePath)
		if err != nil {
			return nil, err
		}
		policy, err = sqlStore.LoadPolicy(context.Background(), policy)
		if err != nil {
			_ = sqlStore.Close()
			return nil, err
		}
	}

	trust, err := identity.NewTrustVerifier(policy, cfg.MaxClockSkew)
	if err != nil {
		if sqlStore != nil {
			_ = sqlStore.Close()
		}
		return nil, err
	}

	tlsCfg, err := buildTLS13Config(&cfg)
	if err != nil {
		if sqlStore != nil {
			_ = sqlStore.Close()
		}
		return nil, err
	}

	rawLn := cfg.HTTPSListener
	if rawLn == nil {
		var listenErr error
		rawLn, listenErr = net.Listen("tcp", cfg.HTTPSListenAddr)
		if listenErr != nil {
			if sqlStore != nil {
				_ = sqlStore.Close()
			}
			return nil, fmt.Errorf("listen https %s: %w", cfg.HTTPSListenAddr, listenErr)
		}
	}
	ln := tls.NewListener(rawLn, tlsCfg)

	var stunSrv *stunserver.Server
	if cfg.EnableSTUN || cfg.STUNPacketConn != nil || cfg.STUNListenAddr != "" {
		stunSrv, err = stunserver.New(stunserver.Config{
			ListenAddr: cfg.STUNListenAddr,
			PacketConn: cfg.STUNPacketConn,
			PerIPRPS:   cfg.STUNPerIPRPS,
			PerIPBurst: cfg.STUNPerIPBurst,
			Logger:     cfg.Logger,
		})
		if err != nil {
			_ = ln.Close()
			if sqlStore != nil {
				_ = sqlStore.Close()
			}
			return nil, err
		}
	}

	s := &Server{
		cfg:           cfg,
		hubOrigin:     origin,
		trust:         trust,
		sqlStore:      sqlStore,
		stunSrv:       stunSrv,
		httpsListener: ln,
		log:           cfg.Logger,
		ipConnRate:    ratelimit.NewKeyedLimiter(cfg.PerIPConnRPS, cfg.PerIPConnBurst, 8192, 5*time.Minute),
		ipConnConc:    ratelimit.NewConcurrencyLimiter(cfg.MaxConnsPerIP, cfg.MaxTotalConns),
		peerMsgRate:   ratelimit.NewKeyedLimiter(cfg.PerPeerMsgRPS, cfg.PerPeerMsgBurst, 8192, 5*time.Minute),
		peerLookRate:  ratelimit.NewKeyedLimiter(cfg.PerPeerLookupRPS, cfg.PerPeerLookupBurst, 8192, 5*time.Minute),
		sessions:      make(map[string][]*peerSession),
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
	if cfg.HubOrigin == "" {
		cfg.HubOrigin = "wss://localhost:8443"
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
	if cfg.PerPeerLookupRPS <= 0 {
		cfg.PerPeerLookupRPS = 20
	}
	if cfg.PerPeerLookupBurst <= 0 {
		cfg.PerPeerLookupBurst = 40
	}
	if cfg.MaxTrackedSessions <= 0 {
		cfg.MaxTrackedSessions = 8192
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
}

func buildTLS13Config(cfg *Config) (*tls.Config, error) {
	var base *tls.Config
	if cfg.TLSConfig != nil {
		base = cfg.TLSConfig.Clone()
	} else {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, errors.New("hub: TLS certificate and key are required")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load hub TLS keypair: %w", err)
		}
		base = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	// Section 4.1: WSS MUST use TLS 1.3 exclusively.
	base.MinVersion = tls.VersionTLS13
	base.MaxVersion = tls.VersionTLS13
	return base, nil
}

// HTTPSAddr returns the bound TCP address of the HTTPS/WSS server.
func (s *Server) HTTPSAddr() net.Addr {
	return s.httpsListener.Addr()
}

// STUNAddr returns the bound UDP address of the STUN Binding service, or nil if disabled.
func (s *Server) STUNAddr() net.Addr {
	if s.stunSrv == nil {
		return nil
	}
	return s.stunSrv.LocalAddr()
}

// HubOrigin returns the canonical WSS origin configured for registration proofs.
func (s *Server) HubOrigin() string {
	return s.hubOrigin
}

// ReloadPolicy updates the active trust and ACL policy and disconnects any newly revoked peers.
func (s *Server) ReloadPolicy(policy identity.PolicyConfig) error {
	if s.sqlStore != nil {
		var err error
		policy, err = s.sqlStore.LoadPolicy(context.Background(), policy)
		if err != nil {
			return err
		}
	}
	if err := s.trust.Reload(policy); err != nil {
		return err
	}
	s.evictRevokedSessions()
	return nil
}

// SetForwardTamperHookForTesting installs a raw frame mutator strictly for T06 negative testing.
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
	s.mu.RUnlock()

	var stunStats stunserver.Stats
	if s.stunSrv != nil {
		stunStats = s.stunSrv.Stats()
	}
	return Stats{
		ActiveSessions:      active,
		RegistrationsOK:     s.regOK.Load(),
		RegistrationsFailed: s.regFailed.Load(),
		LookupsOK:           s.lookOK.Load(),
		LookupsDenied:       s.lookDenied.Load(),
		SignalsForwarded:    s.sigFwd.Load(),
		SignalsRejected:     s.sigRejected.Load(),
		RateLimited:         s.rateDropped.Load(),
		STUN:                stunStats,
	}
}

// Close shuts down the HTTPS/WSS signaling server, active WebSockets, STUN server, and SQLite store.
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
	s.mu.Unlock()

	var stunErr error
	if s.stunSrv != nil {
		stunErr = s.stunSrv.Close()
	}
	var sqlErr error
	if s.sqlStore != nil {
		sqlErr = s.sqlStore.Close()
	}
	s.wg.Wait()
	return errors.Join(stunErr, sqlErr)
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
	remoteIP := extractRemoteIP(r.RemoteAddr)
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

	// Issue single-use 32-byte registration challenge expiring in 60s (Section 3).
	challenge, err := protocol.NewChallenge()
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "internal_error")
		return
	}
	now := s.nowFunc()
	challengeExp := now.Add(s.cfg.ChallengeTTL)

	chalRaw, err := json.Marshal(protocol.ChallengeMessage{
		V:         protocol.Version,
		Type:      protocol.TypeChallenge,
		Challenge: challenge,
		HubOrigin: s.hubOrigin,
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

	// Phase 1: Require registration within ChallengeTTL; challenge is strictly single-use.
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

	ps, errCode, errDetail := s.authenticateRegistration(ctx, conn, cancel, remoteIP, challenge, challengeExp, rawReg)
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
	}); err != nil {
		return
	}

	// Phase 2: Authenticated control-plane loop.
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
	_ context.Context,
	conn *websocket.Conn,
	cancel context.CancelFunc,
	remoteIP string,
	expectedChallenge string,
	challengeExp time.Time,
	raw []byte,
) (*peerSession, string, string) {
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
	if err != nil || canonOrigin != s.hubOrigin {
		return nil, protocol.ErrCodeAuthFailed, "hub_origin mismatch"
	}
	pub, err := identity.DecodePublicKey(reg.PublicKey)
	if err != nil {
		return nil, protocol.ErrCodeAuthFailed, "invalid public_key"
	}
	if err := identity.VerifyRegistrationChallenge(pub, reg.PeerID, expectedChallenge, s.hubOrigin, reg.Proof); err != nil {
		return nil, protocol.ErrCodeAuthFailed, "invalid challenge proof"
	}
	vp, err := s.trust.VerifyPeer(reg.PeerID, pub, reg.Membership)
	if err != nil {
		return nil, protocol.ErrCodeAuthFailed, "peer not trusted or revoked"
	}
	s.trust.CacheVerifiedPeer(vp)

	ps := &peerSession{
		conn:       conn,
		remoteIP:   remoteIP,
		peerID:     vp.PeerID,
		publicKey:  vp.PublicKey,
		membership: vp.Membership,
		cancel:     cancel,
	}
	ps.expiresAt.Store(now.Add(s.cfg.PresenceTTL).UnixNano())

	s.mu.Lock()
	existing := s.sessions[ps.peerID]
	// Prune any closed/expired sessions for this peer first.
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
	s.mu.Unlock()

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

	if s.trust.IsRevoked(ps.peerID) {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeAuthFailed,
		})
		ps.closed.Store(true)
		ps.cancel()
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

	case protocol.TypeLookup:
		s.handleLookup(ctx, ps, raw)

	case protocol.TypeOffer, protocol.TypeAnswer, protocol.TypeCandidate, protocol.TypeEndOfCandidates, protocol.TypeClose:
		s.handlePeerSignal(ctx, ps, raw)

	default:
		// Client MUST NOT send challenge, registered, lookup_result, error, or duplicate register.
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
	}
}

func (s *Server) handleLookup(ctx context.Context, ps *peerSession, raw []byte) {
	if !s.peerLookRate.Allow(ps.peerID) {
		s.rateDropped.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeRateLimited,
		})
		return
	}
	var req protocol.LookupMessage
	if err := jcs.UnmarshalStrict(raw, &req); err != nil {
		s.lookDenied.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeMalformedMessage,
		})
		return
	}
	if err := identity.ValidatePeerID(req.Target); err != nil {
		s.lookDenied.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeUnknownPeer,
		})
		return
	}

	targetSess := s.latestOnlineSession(req.Target)
	var targetPub ed25519.PublicKey
	var targetMem *identity.MembershipRecord
	if targetSess != nil {
		targetPub = targetSess.publicKey
		targetMem = targetSess.membership
	}
	targetVP, err := s.trust.VerifyPeer(req.Target, targetPub, targetMem)
	if err != nil {
		s.lookDenied.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeUnknownPeer,
		})
		return
	}
	if err := s.trust.AuthorizePair(ps.peerID, req.Target, ps.membership, targetVP.Membership); err != nil {
		s.lookDenied.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:    protocol.Version,
			Type: protocol.TypeError,
			Code: protocol.ErrCodeUnauthorizedPair,
		})
		return
	}

	s.lookOK.Add(1)
	_ = ps.sendJSON(ctx, protocol.LookupResultMessage{
		V:          protocol.Version,
		Type:       protocol.TypeLookupResult,
		Target:     req.Target,
		Online:     targetSess != nil,
		PublicKey:  identity.EncodePublicKey(targetVP.PublicKey),
		Membership: targetVP.Membership,
	})
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

	// Section 4.1: Authenticated WSS session determines sender identity.
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

	targetSess := s.latestOnlineSession(env.To)
	var targetPub ed25519.PublicKey
	var targetMem *identity.MembershipRecord
	if targetSess != nil {
		targetPub = targetSess.publicKey
		targetMem = targetSess.membership
	}

	// Verify recipient identity and ACL authorization before signature/presence disclosure.
	targetVP, err := s.trust.VerifyPeer(env.To, targetPub, targetMem)
	if err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      protocol.ErrCodeUnknownPeer,
			SessionID: env.SessionID,
		})
		return
	}
	if err := s.trust.AuthorizePair(ps.peerID, env.To, ps.membership, targetVP.Membership); err != nil {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      protocol.ErrCodeUnauthorizedPair,
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

	// Enforce session, generation, monotonic sequence, replay rejection, and candidate bounds.
	if errCode := s.validateAndRecordSequence(env, now); errCode != "" {
		s.sigRejected.Add(1)
		_ = ps.sendJSON(ctx, protocol.ErrorMessage{
			V:         protocol.Version,
			Type:      protocol.TypeError,
			Code:      errCode,
			SessionID: env.SessionID,
		})
		return
	}

	// Section 4.2: No offline payload mailbox — recipient must be online.
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

func (s *Server) validateAndRecordSequence(env *protocol.SignalEnvelope, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, exists := s.negotiations[env.SessionID]
	if !exists {
		if env.Type != protocol.TypeOffer && env.Type != protocol.TypeClose {
			// New session must begin with offer (or cancellation close) at seq 0.
			if env.Seq != 0 {
				return protocol.ErrCodeReplayedSignaling
			}
		}
		if env.Seq != 0 {
			return protocol.ErrCodeReplayedSignaling
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
		// Verify session belongs to this exact peer pair.
		validPair := (rec.peerA == env.From && rec.peerB == env.To) || (rec.peerA == env.To && rec.peerB == env.From)
		if !validPair || rec.closed {
			return protocol.ErrCodeReplayedSignaling
		}
		if env.Generation < rec.activeGeneration {
			return protocol.ErrCodeStaleGeneration
		}
		if env.Generation > rec.activeGeneration {
			if env.Type != protocol.TypeOffer || env.Seq != 0 {
				return protocol.ErrCodeStaleGeneration
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
		return protocol.ErrCodeReplayedSignaling
	}
	if env.Type == protocol.TypeCandidate {
		if sg.candidateCount >= s.cfg.MaxCandidatesPerGen {
			return protocol.ErrCodeCandidateLimit
		}
		sg.candidateCount++
	}
	sg.nextSeq = env.Seq + 1
	rec.updatedAt = now
	if env.Type == protocol.TypeClose {
		rec.closed = true
	}
	return ""
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

func (s *Server) latestOnlineSession(peerID string) *peerSession {
	all := s.onlineSessions(peerID)
	if len(all) == 0 {
		return nil
	}
	return all[len(all)-1]
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

func (s *Server) evictRevokedSessions() {
	s.mu.Lock()
	var toClose []*peerSession
	for pid, list := range s.sessions {
		if s.trust.IsRevoked(pid) {
			toClose = append(toClose, list...)
			delete(s.sessions, pid)
		}
	}
	s.mu.Unlock()

	for _, ps := range toClose {
		ps.closed.Store(true)
		ps.cancel()
		_ = ps.conn.Close(websocket.StatusPolicyViolation, "peer_revoked")
	}
}

func (s *Server) reapLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			now := s.nowFunc()
			nowNano := now.UnixNano()
			negTTL := s.cfg.SignalingTTL + 2*s.cfg.MaxClockSkew + 2*time.Minute

			var expired []*peerSession
			s.mu.Lock()
			for pid, list := range s.sessions {
				kept := list[:0]
				for _, ps := range list {
					if ps.closed.Load() || nowNano > ps.expiresAt.Load() {
						expired = append(expired, ps)
					} else {
						kept = append(kept, ps)
					}
				}
				if len(kept) == 0 {
					delete(s.sessions, pid)
				} else {
					s.sessions[pid] = kept
				}
			}
			for id, rec := range s.negotiations {
				if now.Sub(rec.updatedAt) > negTTL {
					delete(s.negotiations, id)
				}
			}
			s.mu.Unlock()

			for _, ps := range expired {
				ps.closed.Store(true)
				ps.cancel()
				_ = ps.conn.Close(websocket.StatusPolicyViolation, "presence_expired")
			}
		}
	}
}

func (s *Server) writeErrorDirect(ctx context.Context, conn *websocket.Conn, code, detail, sessionID string) {
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
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
