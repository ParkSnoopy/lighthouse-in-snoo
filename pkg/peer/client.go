package peer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/ice/v5"
	"github.com/pion/logging"
	"github.com/pion/stun/v5"
	"github.com/pion/transport/v5"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/protocol"
)

// ICEServerConfig describes a STUNS/TURNS (or opt-in insecure STUN/TURN) server.
type ICEServerConfig struct {
	URI        string // stuns:host:5349, turns:host:5349[?transport=udp|tcp], or (with AllowInsecureICE) stun:/turn:.
	Username   string // Required for turns: and turn: URIs.
	Credential string // Required for turns: and turn: URIs.
}

type resolvedICEServer struct {
	URI        *stun.URI
	Username   string
	Credential string
}

type knownPeerInfo struct {
	PublicKey   identity.PublicKey
	DisplayName string
	ChannelID   string
}

// Config configures a consent-driven WebRTC peer client connecting via a zero-config universal hub.
// Security relies strictly on peer cryptographic signatures, passphrase-scoped broadcasts,
// local blacklisting, and explicit user Allow/Deny consent for every incoming connection.
type Config struct {
	KeyPair       *identity.KeyPair
	SignalingURL  string // e.g. wss://hub.example.com/v1/signal
	HubOrigin     string // Optional explicit canonical origin; derived from SignalingURL if empty.
	HubPassphrase string // Optional offline passphrase when connecting to a passphrase-gated hub.
	TLSConfig     *tls.Config
	HTTPTransport http.RoundTripper // Optional custom transport (e.g. for tests).

	STUNServerURI       string                    // Optional STUNS/TURNS URI (stuns:/turns: by default; stun:/turn: require AllowInsecureICE).
	TURNServerURI       string                    // Optional explicit TURNS/TURN URI.
	TURNUsername        string                    // Username for explicit turns:/turn: server.
	TURNCredential      string                    // Credential for explicit turns:/turn: server.
	ICEServers          []ICEServerConfig         // Optional additional STUNS/TURNS servers.
	UseHubRelay         *bool                     // Automatically adopt universal relay credentials advertised by hub (default true).
	AllowInsecureICE    bool                      // Explicit opt-in required to allow plaintext stun:/turn: URIs.
	TCPOnly             bool                      // Explicit opt-in to disable all UDP sockets and use ICE-TCP + TLS 1.3/TCP STUNS only.
	ICETCPListenAddr    string                    // Optional TCP listen address for passive ICE-TCP candidates when TCPOnly=true.
	AllowRelay          bool                      // Automatically enabled when a validated turns:/turn: server or universal hub relay is active.
	ICETransportPolicy  webrtc.ICETransportPolicy // Optional ICE transport policy (default ICETransportPolicyAll).
	NetworkTypes        []webrtc.NetworkType      // Defaults to [UDP4, UDP6] (or [TCP4, TCP6] when TCPOnly=true).
	IncludeLoopback     bool
	VNet                transport.Net // Optional virtual network stack (pion/transport/v5/vnet).
	PionLoggerFactory   logging.LoggerFactory
	ProhibitedEndpoints []net.UDPAddr // Additional endpoints forbidden as data destinations.
	BlockHubHostIP      *bool         // Defaults to true when Hub IP is non-loopback/non-local and relay is disabled.

	// Security core: explicit user authorization handler for incoming connections.
	// If nil, ALL incoming connection requests fail closed (ConsentDeny).
	Consent        ConsentHandler
	ConsentTimeout time.Duration // Default 60s.
	Blacklist      *identity.Blacklist
	BlacklistPath  string // Optional 0600 file path for persisting blacklist mutations.

	EnablePacketChannel     bool // Negotiate unordered packet/v1 DataChannel (used for IP TUN packets).
	MaxQueueBytes           int
	OfferToConnectedTimeout time.Duration // Default 30s.
	MaxICERestarts          int           // Default 2.
	ICERestartBackoff       time.Duration // Default 400ms base backoff.
	ICEDisconnectedTimeout  time.Duration
	ICEFailedTimeout        time.Duration
	ICEKeepaliveInterval    time.Duration
	HeartbeatInterval       time.Duration // Default 20s.
	SignalingTTL            time.Duration // Default 60s.
	MaxClockSkew            time.Duration // Default 30s.
	MaxCandidatesPerGen     int           // Default 128.

	DTLSCertAlgorithm identity.Algorithm
	DTLSRSABits       int

	// Strictly for negative testing (simulating a non-conformant DTLS 1.2 peer).
	OverrideDTLSMinVersion dtlsProtocol.Version
	OverrideDTLSMaxVersion dtlsProtocol.Version

	OnSession       func(*Session)
	OnSessionClosed func(remotePeerID, reason string)
	OnPeersChanged  func(channelID string, peers []DiscoveredPeer)
	Logger          *slog.Logger
}

// Client manages a peer's cryptographic identity, WSS control-plane connection,
// passphrase-scoped broadcasting/discovery, local blacklist, explicit incoming consent,
// and DTLS 1.3 WebRTC sessions.
type Client struct {
	cfg         Config
	hubOrigin   string
	netMu       sync.RWMutex
	virtualCIDR netip.Prefix
	localVIP    netip.Addr
	blacklist   *identity.Blacklist
	log         *slog.Logger

	iceMu               sync.RWMutex
	resolvedICE         []resolvedICEServer
	webrtcICEServers    []webrtc.ICEServer
	dtlsUDPTargets      map[string]string
	tlsTCPTargets       map[string]string
	allowRelay          bool
	prohibitedEndpoints []net.UDPAddr
	prohibitedIPs       []net.IP

	tcpMux  webrtc.ICETCPMux
	tcpAddr net.Addr

	wsMu      sync.Mutex
	wsConn    *websocket.Conn
	wsOnline  atomic.Bool
	wsWriteMu sync.Mutex

	mu                 sync.Mutex
	vnet               transport.Net
	channels           map[string]identity.ChannelKeys
	discovered         map[string][]DiscoveredPeer
	knownPeers         map[string]knownPeerInfo
	sessionsByPeer     map[string]*Session
	sessionsByID       map[string]*Session
	closedSessionIDs   map[string]time.Time
	lastSignalRejected atomic.Uint64
	prohibitedRejected atomic.Uint64

	signalCh chan []byte
	stopCh   chan struct{}
	closed   atomic.Bool
	wg       sync.WaitGroup
}

// NewClient validates configuration and constructs a new consent-driven peer Client.
func NewClient(cfgIn *Config) (*Client, error) {
	if cfgIn == nil {
		return nil, errors.New("peer: Config is required")
	}
	cfg := *cfgIn
	if cfg.KeyPair == nil {
		return nil, errors.New("peer: KeyPair is required")
	}
	if err := identity.ValidatePeerID(cfg.KeyPair.PeerID); err != nil {
		return nil, err
	}

	compiledICE, err := compileICEServers(&cfg)
	if err != nil {
		return nil, err
	}
	allowRelay := (cfg.AllowRelay || compiledICE.hasTURN) && !cfg.TCPOnly
	if cfg.TCPOnly {
		if cfg.ICETransportPolicy == webrtc.ICETransportPolicyRelay {
			return nil, fmt.Errorf("%w: relay-only policy is unsupported in TCP-only mode", ErrInvalidICEConfig)
		}
		for _, nt := range cfg.NetworkTypes {
			if nt != webrtc.NetworkTypeTCP4 && nt != webrtc.NetworkTypeTCP6 {
				return nil, fmt.Errorf("%w: UDP network type %s prohibited when TCPOnly=true", ErrInvalidICEConfig, nt.String())
			}
		}
		if len(cfg.NetworkTypes) == 0 {
			cfg.NetworkTypes = []webrtc.NetworkType{webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6}
		}
	} else {
		for _, nt := range cfg.NetworkTypes {
			if nt != webrtc.NetworkTypeUDP4 && nt != webrtc.NetworkTypeUDP6 {
				return nil, fmt.Errorf("%w: non-UDP network type %s", ErrInvalidICEConfig, nt.String())
			}
		}
		if len(cfg.NetworkTypes) == 0 {
			cfg.NetworkTypes = []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6}
		}
	}

	if cfg.OfferToConnectedTimeout <= 0 {
		cfg.OfferToConnectedTimeout = 30 * time.Second
	}
	if cfg.ConsentTimeout <= 0 {
		cfg.ConsentTimeout = 60 * time.Second
	}
	if cfg.MaxICERestarts < 0 {
		cfg.MaxICERestarts = 0
	} else if cfg.MaxICERestarts == 0 {
		cfg.MaxICERestarts = 2
	}
	if cfg.ICERestartBackoff <= 0 {
		cfg.ICERestartBackoff = 400 * time.Millisecond
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 20 * time.Second
	}
	if cfg.SignalingTTL <= 0 {
		cfg.SignalingTTL = protocol.DefaultSignalingTTL
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = protocol.DefaultMaxClockSkew
	}
	if cfg.MaxCandidatesPerGen <= 0 {
		cfg.MaxCandidatesPerGen = protocol.DefaultMaxCandidatesPerGeneration
	}
	if cfg.MaxQueueBytes <= 0 {
		cfg.MaxQueueBytes = DefaultApplicationQueueBytes
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	originSource := cfg.HubOrigin
	if originSource == "" {
		originSource = cfg.SignalingURL
	}
	origin, err := identity.CanonicalizeOrigin(originSource)
	if err != nil {
		return nil, err
	}

	bl := cfg.Blacklist
	if bl == nil {
		if cfg.BlacklistPath != "" {
			bl, err = identity.LoadBlacklist(cfg.BlacklistPath)
			if err != nil {
				return nil, err
			}
		} else {
			bl = identity.NewBlacklist()
		}
	}

	var (
		tcpMux  webrtc.ICETCPMux
		tcpAddr net.Addr
	)
	if cfg.TCPOnly {
		tcpLn, listenErr := listenICETCP(&cfg)
		if listenErr != nil {
			return nil, fmt.Errorf("peer: listen ICE-TCP: %w", listenErr)
		}
		tcpAddr = tcpLn.Addr()
		lf := cfg.PionLoggerFactory
		if lf == nil {
			dlf := logging.NewDefaultLoggerFactory()
			dlf.DefaultLogLevel = logging.LogLevelError
			lf = dlf
		}
		tcpMux = webrtc.NewICETCPMux(lf.NewLogger("ice-tcp"), tcpLn, 8)
	}

	prohibitedEPs, prohibitedIPs := deriveProhibitedHubTargets(&cfg, compiledICE.resolved, allowRelay)

	c := &Client{
		cfg:                 cfg,
		hubOrigin:           origin,
		blacklist:           bl,
		log:                 cfg.Logger,
		resolvedICE:         compiledICE.resolved,
		webrtcICEServers:    compiledICE.webrtcServers,
		dtlsUDPTargets:      compiledICE.dtlsUDPTargets,
		tlsTCPTargets:       compiledICE.tlsTCPTargets,
		allowRelay:          allowRelay,
		tcpMux:              tcpMux,
		tcpAddr:             tcpAddr,
		prohibitedEndpoints: prohibitedEPs,
		prohibitedIPs:       prohibitedIPs,
		vnet:                cfg.VNet,
		channels:            make(map[string]identity.ChannelKeys),
		discovered:          make(map[string][]DiscoveredPeer),
		knownPeers:          make(map[string]knownPeerInfo),
		sessionsByPeer:      make(map[string]*Session),
		sessionsByID:        make(map[string]*Session),
		closedSessionIDs:    make(map[string]time.Time),
		signalCh:            make(chan []byte, 512),
		stopCh:              make(chan struct{}),
	}
	c.wg.Add(1)
	go c.signalWorkerLoop()
	return c, nil
}

type compiledICEServers struct {
	resolved       []resolvedICEServer
	webrtcServers  []webrtc.ICEServer
	dtlsUDPTargets map[string]string
	tlsTCPTargets  map[string]string
	hasTURN        bool
}

func compileICEServers(cfg *Config) (compiledICEServers, error) {
	var entries []ICEServerConfig
	if strings.TrimSpace(cfg.STUNServerURI) != "" {
		entries = append(entries, ICEServerConfig{
			URI:        cfg.STUNServerURI,
			Username:   cfg.TURNUsername,
			Credential: cfg.TURNCredential,
		})
	}
	if strings.TrimSpace(cfg.TURNServerURI) != "" {
		entries = append(entries, ICEServerConfig{
			URI:        cfg.TURNServerURI,
			Username:   cfg.TURNUsername,
			Credential: cfg.TURNCredential,
		})
	}
	entries = append(entries, cfg.ICEServers...)
	return compileICEServerEntries(entries, cfg.AllowInsecureICE, cfg.TCPOnly)
}

func compileICEServerEntries(entries []ICEServerConfig, allowInsecure, tcpOnly bool) (compiledICEServers, error) {
	out := compiledICEServers{
		dtlsUDPTargets: make(map[string]string),
		tlsTCPTargets:  make(map[string]string),
	}

	for _, entry := range entries {
		if strings.TrimSpace(entry.URI) == "" {
			continue
		}
		parsed, vErr := ValidateICEServerURIWithMode(entry.URI, allowInsecure, tcpOnly)
		if vErr != nil {
			return compiledICEServers{}, vErr
		}
		if parsed == nil {
			continue
		}
		isTURN := parsed.Scheme == stun.SchemeTypeTURN || parsed.Scheme == stun.SchemeTypeTURNS
		if isTURN {
			if strings.TrimSpace(entry.Username) == "" || entry.Credential == "" {
				return compiledICEServers{}, fmt.Errorf("%w: TURN/TURNS URI %q requires username and credential", ErrInvalidICEConfig, entry.URI)
			}
			out.hasTURN = true
		}

		hostPort := net.JoinHostPort(parsed.Host, strconv.Itoa(parsed.Port))
		out.resolved = append(out.resolved, resolvedICEServer{
			URI:        parsed,
			Username:   entry.Username,
			Credential: entry.Credential,
		})

		if tcpOnly {
			if parsed.IsSecure() {
				out.tlsTCPTargets[hostPort] = parsed.Host
			}
			continue
		}

		var srv webrtc.ICEServer
		switch {
		case parsed.Scheme == stun.SchemeTypeSTUNS && parsed.Proto == stun.ProtoTypeUDP:
			out.dtlsUDPTargets[hostPort] = parsed.Host
			srv = webrtc.ICEServer{URLs: []string{"stun:" + hostPort}}

		case parsed.Scheme == stun.SchemeTypeTURNS && parsed.Proto == stun.ProtoTypeUDP:
			out.dtlsUDPTargets[hostPort] = parsed.Host
			srv = webrtc.ICEServer{
				URLs:           []string{"turn:" + hostPort + "?transport=udp"},
				Username:       entry.Username,
				Credential:     entry.Credential,
				CredentialType: webrtc.ICECredentialTypePassword,
			}

		case parsed.Scheme == stun.SchemeTypeTURNS && parsed.Proto == stun.ProtoTypeTCP:
			out.tlsTCPTargets[hostPort] = parsed.Host
			srv = webrtc.ICEServer{
				URLs:           []string{"turns:" + hostPort + "?transport=tcp"},
				Username:       entry.Username,
				Credential:     entry.Credential,
				CredentialType: webrtc.ICECredentialTypePassword,
			}

		case parsed.Scheme == stun.SchemeTypeSTUNS && parsed.Proto == stun.ProtoTypeTCP:
			srv = webrtc.ICEServer{URLs: []string{parsed.String()}}

		case isTURN:
			srv = webrtc.ICEServer{
				URLs:           []string{parsed.String()},
				Username:       entry.Username,
				Credential:     entry.Credential,
				CredentialType: webrtc.ICECredentialTypePassword,
			}

		default:
			srv = webrtc.ICEServer{URLs: []string{parsed.String()}}
		}
		out.webrtcServers = append(out.webrtcServers, srv)
	}
	return out, nil
}

func (c *Client) applyHubNetwork(virtualCIDRStr, assignedIPStr string) error {
	cidr := identity.DefaultVirtualCIDR()
	if strings.TrimSpace(virtualCIDRStr) != "" {
		parsed, err := identity.ParseVirtualCIDR(virtualCIDRStr)
		if err != nil {
			return fmt.Errorf("peer: hub advertised invalid virtual_cidr %q: %w", virtualCIDRStr, err)
		}
		cidr = parsed
	}
	expectedVIP, err := identity.VirtualIPv4InPrefix(c.cfg.KeyPair.PeerID, cidr)
	if err != nil {
		return err
	}
	if strings.TrimSpace(assignedIPStr) != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(assignedIPStr))
		if err != nil || !addr.Is4() || !cidr.Contains(addr) || addr != expectedVIP {
			return fmt.Errorf("peer: hub advertised invalid assigned_ip %q for %s", assignedIPStr, cidr.String())
		}
	}
	c.netMu.Lock()
	c.virtualCIDR = cidr
	c.localVIP = expectedVIP
	c.netMu.Unlock()
	return nil
}

func (c *Client) applyHubRelay(relay *protocol.RelayInfo) {
	if relay == nil || len(relay.URIs) == 0 || c.cfg.TCPOnly {
		return
	}
	if c.cfg.UseHubRelay != nil && !*c.cfg.UseHubRelay {
		return
	}
	entries := make([]ICEServerConfig, 0, len(relay.URIs))
	for _, u := range relay.URIs {
		entries = append(entries, ICEServerConfig{
			URI:        u,
			Username:   relay.Username,
			Credential: relay.Credential,
		})
	}
	compiled, err := compileICEServerEntries(entries, c.cfg.AllowInsecureICE, false)
	if err != nil || len(compiled.resolved) == 0 {
		return
	}

	c.iceMu.Lock()
	c.resolvedICE = append(c.resolvedICE, compiled.resolved...)
	c.webrtcICEServers = append(c.webrtcICEServers, compiled.webrtcServers...)
	for k, v := range compiled.dtlsUDPTargets {
		c.dtlsUDPTargets[k] = v
	}
	for k, v := range compiled.tlsTCPTargets {
		c.tlsTCPTargets[k] = v
	}
	if compiled.hasTURN {
		c.allowRelay = true
	}
	c.prohibitedEndpoints, c.prohibitedIPs = deriveProhibitedHubTargets(&c.cfg, c.resolvedICE, c.allowRelay)
	c.iceMu.Unlock()
}

func deriveProhibitedHubTargets(cfg *Config, servers []resolvedICEServer, allowRelay bool) ([]net.UDPAddr, []net.IP) {
	endpoints := append([]net.UDPAddr(nil), cfg.ProhibitedEndpoints...)
	var ips []net.IP

	localIPs := gatherLocalHostIPs()
	isLocal := func(ip net.IP) bool {
		if ip.IsLoopback() {
			return true
		}
		for _, lip := range localIPs {
			if lip.Equal(ip) {
				return true
			}
		}
		return false
	}

	addEndpoint := func(host string, port int) {
		if ip := net.ParseIP(host); ip != nil {
			if port > 0 {
				endpoints = append(endpoints, net.UDPAddr{IP: ip, Port: port})
			}
			blockIP := !isLocal(ip) && !allowRelay
			if cfg.BlockHubHostIP != nil {
				blockIP = *cfg.BlockHubHostIP
			}
			if blockIP {
				ips = append(ips, ip)
			}
			return
		}
		resolved, err := net.LookupIP(host)
		if err != nil {
			return
		}
		for _, ip := range resolved {
			if port > 0 {
				endpoints = append(endpoints, net.UDPAddr{IP: ip, Port: port})
			}
			blockIP := !isLocal(ip) && !allowRelay
			if cfg.BlockHubHostIP != nil {
				blockIP = *cfg.BlockHubHostIP
			}
			if blockIP {
				ips = append(ips, ip)
			}
		}
	}

	if u, err := url.Parse(cfg.SignalingURL); err == nil && u.Hostname() != "" {
		port := 443
		if u.Port() != "" {
			if p, pErr := strconv.Atoi(u.Port()); pErr == nil {
				port = p
			}
		}
		addEndpoint(u.Hostname(), port)
	}
	for _, srv := range servers {
		if srv.URI != nil {
			addEndpoint(srv.URI.Host, srv.URI.Port)
		}
	}

	return endpoints, ips
}

func gatherLocalHostIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
			out = append(out, ipnet.IP)
		}
	}
	return out
}

// PeerID returns this client's persistent cryptographic peer_id.
func (c *Client) PeerID() string {
	return c.cfg.KeyPair.PeerID
}

// VirtualIP returns this client's hub-assigned TUN IPv4 address (zero until Register succeeds).
func (c *Client) VirtualIP() netip.Addr {
	c.netMu.RLock()
	defer c.netMu.RUnlock()
	return c.localVIP
}

// VirtualCIDR returns the virtual IPv4 subnet advertised by the hub on Register.
func (c *Client) VirtualCIDR() netip.Prefix {
	c.netMu.RLock()
	defer c.netMu.RUnlock()
	return c.virtualCIDR
}

func (c *Client) effectiveVirtualCIDR() netip.Prefix {
	c.netMu.RLock()
	cidr := c.virtualCIDR
	c.netMu.RUnlock()
	if !cidr.IsValid() {
		return identity.DefaultVirtualCIDR()
	}
	return cidr
}

// ICETCPAddr returns the bound passive ICE-TCP listen address when TCPOnly=true, or nil otherwise.
func (c *Client) ICETCPAddr() net.Addr {
	return c.tcpAddr
}

// Online reports whether the WSS control-plane connection to the hub is currently active.
func (c *Client) Online() bool {
	return c.wsOnline.Load()
}

func (c *Client) candidatePolicySnapshot() (policy CandidatePolicy, prohibitedEPs []net.UDPAddr, prohibitedIPs []net.IP) {
	c.iceMu.RLock()
	defer c.iceMu.RUnlock()
	return CandidatePolicy{
		AllowRelay: c.allowRelay && !c.cfg.TCPOnly,
		TCPOnly:    c.cfg.TCPOnly,
	}, append([]net.UDPAddr(nil), c.prohibitedEndpoints...), append([]net.IP(nil), c.prohibitedIPs...)
}

func listenICETCP(cfg *Config) (net.Listener, error) {
	var hasTCP4, hasTCP6 bool
	for _, nt := range cfg.NetworkTypes {
		if nt == webrtc.NetworkTypeTCP4 {
			hasTCP4 = true
		} else if nt == webrtc.NetworkTypeTCP6 {
			hasTCP6 = true
		}
	}
	addr := strings.TrimSpace(cfg.ICETCPListenAddr)
	switch {
	case addr != "" && hasTCP4 && !hasTCP6:
		return net.Listen("tcp4", addr)
	case addr != "" && hasTCP6 && !hasTCP4:
		return net.Listen("tcp6", addr)
	case addr != "":
		return net.Listen("tcp", addr)
	case hasTCP4 && !hasTCP6:
		return net.Listen("tcp4", "0.0.0.0:0")
	case hasTCP6 && !hasTCP4:
		return net.Listen("tcp6", "[::]:0")
	default:
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			return net.Listen("tcp4", "0.0.0.0:0")
		}
		return ln, nil
	}
}

// RejectedSignalCount returns how many invalid/replayed/tampered signaling envelopes were rejected.
func (c *Client) RejectedSignalCount() uint64 {
	return c.lastSignalRejected.Load()
}

// ProhibitedCandidateCount returns how many relay/wrong-transport/hub-endpoint candidates were blocked.
func (c *Client) ProhibitedCandidateCount() uint64 {
	return c.prohibitedRejected.Load()
}

// Blacklist blocks peerID locally, drops its broadcasts, and terminates any active session with it.
func (c *Client) Blacklist(peerID string) error {
	if err := c.blacklist.Add(peerID); err != nil {
		return err
	}
	if c.cfg.BlacklistPath != "" {
		if err := c.blacklist.Save(c.cfg.BlacklistPath); err != nil {
			return err
		}
	}

	c.mu.Lock()
	activeSess := c.sessionsByPeer[peerID]
	var changedChannels []string
	var changedSnapshots [][]DiscoveredPeer
	for chID, list := range c.discovered {
		filtered := make([]DiscoveredPeer, 0, len(list))
		removed := false
		for i := range list {
			if list[i].PeerID == peerID {
				removed = true
				continue
			}
			filtered = append(filtered, list[i])
		}
		if removed {
			c.discovered[chID] = filtered
			changedChannels = append(changedChannels, chID)
			changedSnapshots = append(changedSnapshots, slices.Clone(filtered))
		}
	}
	c.mu.Unlock()

	if activeSess != nil {
		_ = activeSess.CloseWithReason("blacklisted")
	}
	if c.cfg.OnPeersChanged != nil {
		for i, chID := range changedChannels {
			go c.cfg.OnPeersChanged(chID, changedSnapshots[i])
		}
	}
	return nil
}

// Unblacklist removes peerID from the local blacklist.
func (c *Client) Unblacklist(peerID string) error {
	c.blacklist.Remove(peerID)
	if c.cfg.BlacklistPath != "" {
		return c.blacklist.Save(c.cfg.BlacklistPath)
	}
	return nil
}

// IsBlacklisted reports whether peerID is currently blacklisted locally.
func (c *Client) IsBlacklisted(peerID string) bool {
	return c.blacklist.Contains(peerID)
}

// BlacklistedPeers returns a sorted snapshot of locally blacklisted peer_ids.
func (c *Client) BlacklistedPeers() []string {
	return c.blacklist.List()
}

// ActiveSessions returns a snapshot of all currently tracked sessions.
func (c *Client) ActiveSessions() []*Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Session, 0, len(c.sessionsByPeer))
	for _, s := range c.sessionsByPeer {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RemotePeerID() < out[j].RemotePeerID()
	})
	return out
}

// UpdateNetwork swaps the virtual network stack and triggers bounded ICE restart on active sessions.
func (c *Client) UpdateNetwork(newVNet transport.Net) {
	c.mu.Lock()
	c.vnet = newVNet
	var active []*Session
	for _, s := range c.sessionsByPeer {
		active = append(active, s)
	}
	c.mu.Unlock()

	for _, s := range active {
		s.triggerNetworkChange()
	}
}

// Register connects to the Lighthouse WSS endpoint over TLS 1.3 and completes
// single-use challenge-response registration (plus optional offline hub passphrase proof).
func (c *Client) Register(ctx context.Context) error {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if c.cfg.TLSConfig != nil {
		tlsCfg = c.cfg.TLSConfig.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.MaxVersion = tls.VersionTLS13
	}

	httpClient := &http.Client{
		Transport: c.cfg.HTTPTransport,
	}
	if httpClient.Transport == nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: false,
		}
	}

	conn, _, err := websocket.Dial(ctx, c.cfg.SignalingURL, &websocket.DialOptions{
		HTTPClient: httpClient,
	})
	if err != nil {
		return fmt.Errorf("dial signaling wss: %w", err)
	}
	conn.SetReadLimit(protocol.MaxSignalingMessageSize)

	mType, rawChal, err := conn.Read(ctx)
	if err != nil {
		_ = conn.CloseNow()
		return fmt.Errorf("read hub challenge: %w", err)
	}
	if mType != websocket.MessageText {
		_ = conn.CloseNow()
		return errors.New("peer: unexpected non-text challenge frame")
	}

	var chal protocol.ChallengeMessage
	if err := jcs.UnmarshalStrict(rawChal, &chal); err != nil {
		_ = conn.CloseNow()
		return fmt.Errorf("parse challenge: %w", err)
	}
	if chal.V != protocol.Version || chal.Type != protocol.TypeChallenge || len(chal.Challenge) < 43 {
		_ = conn.CloseNow()
		return errors.New("peer: malformed challenge from hub")
	}
	chalOrigin, err := identity.CanonicalizeOrigin(chal.HubOrigin)
	if err != nil || chalOrigin != c.hubOrigin {
		_ = conn.CloseNow()
		return fmt.Errorf("%w: hub claimed %q, expected %q", identity.ErrInvalidOrigin, chal.HubOrigin, c.hubOrigin)
	}

	proof, err := c.cfg.KeyPair.SignRegistrationChallenge(chal.Challenge, c.hubOrigin)
	if err != nil {
		_ = conn.CloseNow()
		return err
	}

	hubAuth := ""
	if chal.PassphraseRequired || strings.TrimSpace(c.cfg.HubPassphrase) != "" {
		if strings.TrimSpace(c.cfg.HubPassphrase) == "" {
			_ = conn.CloseNow()
			return errors.New("peer: hub requires an offline passphrase")
		}
		hubAuth, err = identity.SignHubPassphraseProof(c.cfg.HubPassphrase, chal.Challenge, c.hubOrigin, c.cfg.KeyPair.PeerID)
		if err != nil {
			_ = conn.CloseNow()
			return err
		}
	}

	regPayload, err := json.Marshal(protocol.RegisterMessage{
		V:         protocol.Version,
		Type:      protocol.TypeRegister,
		PeerID:    c.cfg.KeyPair.PeerID,
		PublicKey: identity.EncodePublicKey(c.cfg.KeyPair.PublicKey),
		HubOrigin: c.hubOrigin,
		Challenge: chal.Challenge,
		Proof:     proof,
		HubAuth:   hubAuth,
	})
	if err != nil {
		_ = conn.CloseNow()
		return err
	}

	if err := conn.Write(ctx, websocket.MessageText, regPayload); err != nil {
		_ = conn.CloseNow()
		return fmt.Errorf("send register: %w", err)
	}

	mType, rawResp, err := conn.Read(ctx)
	if err != nil {
		_ = conn.CloseNow()
		return fmt.Errorf("read register response: %w", err)
	}
	if mType != websocket.MessageText {
		_ = conn.CloseNow()
		return errors.New("peer: unexpected binary register response")
	}

	hdr, err := protocol.PeekHeader(rawResp, protocol.MaxSignalingMessageSize)
	if err != nil {
		_ = conn.CloseNow()
		return err
	}
	if hdr.Type == protocol.TypeError {
		var em protocol.ErrorMessage
		_ = jcs.UnmarshalStrict(rawResp, &em)
		_ = conn.CloseNow()
		return fmt.Errorf("hub rejected registration: %s (%s)", em.Code, em.Detail)
	}
	if hdr.Type != protocol.TypeRegistered {
		_ = conn.CloseNow()
		return fmt.Errorf("unexpected registration response type %q", hdr.Type)
	}

	var regOK protocol.RegisteredMessage
	if err := jcs.UnmarshalStrict(rawResp, &regOK); err != nil || regOK.PeerID != c.cfg.KeyPair.PeerID {
		_ = conn.CloseNow()
		return errors.New("peer: invalid registered confirmation")
	}

	if err := c.applyHubNetwork(regOK.VirtualCIDR, regOK.AssignedIP); err != nil {
		_ = conn.CloseNow()
		return err
	}
	c.applyHubRelay(regOK.Relay)

	hbInterval := c.cfg.HeartbeatInterval
	if regOK.HeartbeatIntervalSec > 0 {
		srvHB := time.Duration(regOK.HeartbeatIntervalSec) * time.Second
		if srvHB < hbInterval {
			hbInterval = srvHB
		}
	}

	c.wsMu.Lock()
	oldConn := c.wsConn
	c.wsConn = conn
	c.wsOnline.Store(true)
	c.wsMu.Unlock()
	if oldConn != nil {
		_ = oldConn.CloseNow()
	}

	wsDone := make(chan struct{})
	c.wg.Add(2)
	go c.wsReadLoop(conn, wsDone)
	go c.wsHeartbeatLoop(hbInterval, wsDone)
	return nil
}

// JoinChannel subscribes to broadcasts scoped to the given offline passphrase without broadcasting self.
func (c *Client) JoinChannel(ctx context.Context, passphrase string) (string, error) {
	keys, err := identity.DeriveChannelKeys(passphrase)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.channels[keys.ChannelID] = keys
	c.mu.Unlock()

	raw, err := json.Marshal(protocol.ChannelJoinMessage{
		V:         protocol.Version,
		Type:      protocol.TypeChannelJoin,
		ChannelID: keys.ChannelID,
	})
	if err != nil {
		return "", err
	}
	if err := c.sendWS(ctx, raw); err != nil {
		return "", err
	}
	return keys.ChannelID, nil
}

// LeaveChannel unsubscribes from a passphrase-scoped channel (accepting either raw passphrase or channelID).
func (c *Client) LeaveChannel(ctx context.Context, passphraseOrChannelID string) error {
	chID := passphraseOrChannelID
	if identity.ValidateChannelID(chID) != nil {
		keys, err := identity.DeriveChannelKeys(passphraseOrChannelID)
		if err != nil {
			return err
		}
		chID = keys.ChannelID
	}
	c.mu.Lock()
	delete(c.channels, chID)
	delete(c.discovered, chID)
	c.mu.Unlock()

	raw, err := json.Marshal(protocol.ChannelLeaveMessage{
		V:         protocol.Version,
		Type:      protocol.TypeChannelLeave,
		ChannelID: chID,
	})
	if err != nil {
		return err
	}
	return c.sendWS(ctx, raw)
}

// SetBroadcast explicitly enables or disables broadcasting this peer's presence to peers
// sharing the exact offline passphrase.
func (c *Client) SetBroadcast(ctx context.Context, enabled bool, passphrase, displayName string) (string, error) {
	keys, err := identity.DeriveChannelKeys(passphrase)
	if err != nil {
		return "", err
	}
	sealed := ""
	if enabled {
		vipStr := ""
		if vip := c.VirtualIP(); vip.IsValid() {
			vipStr = vip.String()
		}
		sealed, err = identity.SealBroadcastMeta(keys.AuthKey, c.PeerID(), keys.ChannelID, identity.BroadcastMeta{
			DisplayName: strings.TrimSpace(displayName),
			VirtualIP:   vipStr,
		})
		if err != nil {
			return "", err
		}
	}
	_, raw, err := protocol.SignBroadcast(c.cfg.KeyPair, keys.ChannelID, enabled, sealed, time.Now().Unix())
	if err != nil {
		return "", err
	}
	if err := c.sendWS(ctx, raw); err != nil {
		return "", err
	}
	return keys.ChannelID, nil
}

// DiscoveredPeers returns currently active broadcasters for channelID (or across all joined channels if empty).
func (c *Client) DiscoveredPeers(channelID string) []DiscoveredPeer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if channelID != "" {
		return slices.Clone(c.discovered[channelID])
	}
	var out []DiscoveredPeer
	for _, list := range c.discovered {
		out = append(out, list...)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

// Close shuts down all peer sessions, ICE-TCP mux, and the WSS signaling connection.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(c.stopCh)

	c.mu.Lock()
	var sessions []*Session
	for _, s := range c.sessionsByPeer {
		sessions = append(sessions, s)
	}
	c.sessionsByPeer = make(map[string]*Session)
	c.sessionsByID = make(map[string]*Session)
	c.mu.Unlock()

	for _, s := range sessions {
		_ = s.CloseWithReason("client_shutdown")
	}

	c.wsMu.Lock()
	conn := c.wsConn
	c.wsConn = nil
	c.wsOnline.Store(false)
	c.wsMu.Unlock()
	if conn != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "shutdown")
	}

	var tcpErr error
	if c.tcpMux != nil {
		tcpErr = c.tcpMux.Close()
	}

	c.wg.Wait()
	return tcpErr
}

func (c *Client) sendWS(ctx context.Context, raw []byte) error {
	c.wsMu.Lock()
	conn := c.wsConn
	online := c.wsOnline.Load()
	c.wsMu.Unlock()
	if conn == nil || !online {
		return ErrHubDisconnected
	}

	c.wsWriteMu.Lock()
	defer c.wsWriteMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, raw)
}

func (c *Client) wsHeartbeatLoop(interval time.Duration, wsDone <-chan struct{}) {
	defer c.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	hbRaw, _ := json.Marshal(protocol.HeartbeatMessage{
		V:    protocol.Version,
		Type: protocol.TypeHeartbeat,
	})
	for {
		select {
		case <-c.stopCh:
			return
		case <-wsDone:
			return
		case <-ticker.C:
			if err := c.sendWS(context.Background(), hbRaw); err != nil {
				return
			}
		}
	}
}

func (c *Client) wsReadLoop(conn *websocket.Conn, wsDone chan struct{}) {
	defer c.wg.Done()
	defer close(wsDone)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-c.stopCh:
			cancel()
		case <-wsDone:
			cancel()
		}
	}()

	for {
		mType, raw, err := conn.Read(ctx)
		if err != nil {
			c.handleWSLoss(conn)
			return
		}
		if mType != websocket.MessageText {
			c.lastSignalRejected.Add(1)
			continue
		}
		c.dispatchControlMessage(raw)
	}
}

func (c *Client) handleWSLoss(lostConn *websocket.Conn) {
	c.wsMu.Lock()
	if c.wsConn == lostConn {
		c.wsConn = nil
		c.wsOnline.Store(false)
	}
	c.wsMu.Unlock()

	c.mu.Lock()
	var toAbandon []*Session
	for _, s := range c.sessionsByID {
		st := s.State()
		if st == StateDiscovering || st == StateNegotiating || st == StateAuthenticating || st == StateReconnecting {
			toAbandon = append(toAbandon, s)
		}
	}
	c.mu.Unlock()

	for _, s := range toAbandon {
		s.failClosed("wss_lost_during_negotiation", ErrHubDisconnected)
	}
}

func (c *Client) dispatchControlMessage(raw []byte) {
	hdr, err := protocol.PeekHeader(raw, protocol.MaxSignalingMessageSize)
	if err != nil {
		c.lastSignalRejected.Add(1)
		return
	}

	switch hdr.Type {
	case protocol.TypeChannelPeers:
		c.handleChannelPeers(raw)

	case protocol.TypeError, protocol.TypeOffer, protocol.TypeAnswer, protocol.TypeCandidate, protocol.TypeEndOfCandidates, protocol.TypeClose:
		cp := append([]byte(nil), raw...)
		select {
		case c.signalCh <- cp:
		case <-c.stopCh:
		}
	}
}

func (c *Client) handleChannelPeers(raw []byte) {
	var msg protocol.ChannelPeersMessage
	if err := jcs.UnmarshalStrict(raw, &msg); err != nil {
		c.lastSignalRejected.Add(1)
		return
	}

	c.mu.Lock()
	keys, joined := c.channels[msg.ChannelID]
	c.mu.Unlock()
	if !joined {
		return
	}

	peers := make([]DiscoveredPeer, 0, len(msg.Peers))
	for _, bp := range msg.Peers {
		if bp.PeerID == c.PeerID() || c.blacklist.Contains(bp.PeerID) {
			continue
		}
		pub, err := protocol.VerifyBroadcastPeer(msg.ChannelID, bp)
		if err != nil {
			c.lastSignalRejected.Add(1)
			continue
		}
		meta, err := identity.OpenBroadcastMeta(keys.AuthKey, bp.PeerID, msg.ChannelID, bp.SealedMeta)
		if err != nil {
			// Metadata cannot be opened with our offline passphrase -> discard silently.
			c.lastSignalRejected.Add(1)
			continue
		}
		vip, err := identity.VirtualIPv4InPrefix(bp.PeerID, c.effectiveVirtualCIDR())
		if err != nil {
			continue
		}
		dp := DiscoveredPeer{
			PeerID:      bp.PeerID,
			PublicKey:   pub,
			Algorithm:   pub.Algorithm,
			VirtualIP:   vip,
			DisplayName: meta.DisplayName,
			ChannelID:   msg.ChannelID,
			Timestamp:   bp.Timestamp,
		}
		peers = append(peers, dp)

		c.mu.Lock()
		c.knownPeers[bp.PeerID] = knownPeerInfo{
			PublicKey:   pub,
			DisplayName: meta.DisplayName,
			ChannelID:   msg.ChannelID,
		}
		c.mu.Unlock()
	}

	c.mu.Lock()
	c.discovered[msg.ChannelID] = peers
	c.mu.Unlock()

	if c.cfg.OnPeersChanged != nil {
		go c.cfg.OnPeersChanged(msg.ChannelID, slices.Clone(peers))
	}
}

func (c *Client) signalWorkerLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.stopCh:
			return
		case raw := <-c.signalCh:
			hdr, hErr := protocol.PeekHeader(raw, protocol.MaxSignalingMessageSize)
			if hErr == nil && hdr.Type == protocol.TypeError {
				c.handleHubError(raw)
				continue
			}
			if err := c.handlePeerEnvelope(raw); err != nil {
				c.lastSignalRejected.Add(1)
				c.log.Warn("rejected peer signaling envelope", "err", err)
			}
		}
	}
}

func (c *Client) handleHubError(raw []byte) {
	var em protocol.ErrorMessage
	if err := jcs.UnmarshalStrict(raw, &em); err != nil {
		return
	}
	if em.SessionID == "" {
		return
	}
	c.mu.Lock()
	sess := c.sessionsByID[em.SessionID]
	c.mu.Unlock()
	if sess == nil {
		return
	}
	cause := fmt.Errorf("hub error: %s", em.Code)
	switch em.Code {
	case protocol.ErrCodePeerOffline:
		cause = fmt.Errorf("%w: %s", ErrPeerOfflineOrDenied, em.Code)
	case protocol.ErrCodeNotAuthorized:
		if em.Detail != "" {
			cause = fmt.Errorf("%w: %s", ErrNotAuthorized, em.Detail)
		} else {
			cause = ErrNotAuthorized
		}
	}
	sess.failClosed(em.Code, cause)
}

// InjectRawEnvelopeForTesting feeds a raw signaling JSON payload directly into the
// client's envelope verifier (used for unit/acceptance security testing).
func (c *Client) InjectRawEnvelopeForTesting(raw []byte) error {
	err := c.handlePeerEnvelope(raw)
	if err != nil {
		c.lastSignalRejected.Add(1)
	}
	return err
}

func (c *Client) resolveSenderPublicKey(env *protocol.SignalEnvelope, sess *Session) (identity.PublicKey, error) {
	if env.PublicKey != "" {
		pub, err := identity.DecodePublicKey(env.PublicKey)
		if err != nil {
			return identity.PublicKey{}, err
		}
		derived, err := identity.PeerIDFromPublicKey(pub)
		if err != nil || derived != env.From {
			return identity.PublicKey{}, identity.ErrPeerIDMismatch
		}
		if sess != nil && !sess.remotePub.IsZero() && !sess.remotePub.Equal(pub) {
			return identity.PublicKey{}, identity.ErrPeerIDMismatch
		}
		return pub, nil
	}
	if sess != nil && !sess.remotePub.IsZero() {
		return sess.remotePub, nil
	}
	c.mu.Lock()
	kp, ok := c.knownPeers[env.From]
	c.mu.Unlock()
	if ok && !kp.PublicKey.IsZero() {
		return kp.PublicKey, nil
	}
	return identity.PublicKey{}, protocol.ErrInvalidSignature
}

func (c *Client) sendImmediateClose(toPeerID, sessionID string, gen uint32, reason string) {
	if !c.wsOnline.Load() {
		return
	}
	_, raw, err := protocol.SignEnvelope(
		c.cfg.KeyPair,
		protocol.TypeClose,
		toPeerID,
		sessionID,
		gen,
		0,
		time.Now().Add(c.cfg.SignalingTTL).Unix(),
		protocol.CloseBody{Reason: reason},
	)
	if err != nil {
		return
	}
	_ = c.sendWS(context.Background(), raw)
}

func (c *Client) handlePeerEnvelope(raw []byte) error {
	env, err := protocol.ParseUnsignedEnvelope(raw, protocol.MaxSignalingMessageSize)
	if err != nil {
		return err
	}
	if env.To != c.PeerID() {
		return protocol.ErrInvalidEnvelope
	}

	c.mu.Lock()
	if _, wasClosed := c.closedSessionIDs[env.SessionID]; wasClosed {
		c.mu.Unlock()
		return ErrReplayedSignaling
	}
	sessByID := c.sessionsByID[env.SessionID]
	sessByPeer := c.sessionsByPeer[env.From]
	known := c.knownPeers[env.From]
	c.mu.Unlock()

	senderPub, err := c.resolveSenderPublicKey(env, sessByID)
	if err != nil {
		return err
	}
	if err := protocol.VerifyEnvelopeSignature(env, senderPub, time.Now(), c.cfg.SignalingTTL, c.cfg.MaxClockSkew); err != nil {
		return err
	}

	if env.Type == protocol.TypeOffer {
		// Blacklisted peers are rejected immediately without bothering the user.
		if c.blacklist.Contains(env.From) {
			c.sendImmediateClose(env.From, env.SessionID, env.Generation, "blacklisted")
			return ErrPeerBlacklisted
		}

		// Pre-validate remote SDP before prompting the user or creating WebRTC state.
		var body protocol.SDPBody
		if err := jcs.UnmarshalStrict(env.Body, &body); err != nil {
			return err
		}
		candPolicy, prohibEPs, prohibIPs := c.candidatePolicySnapshot()
		info, err := ValidateAndInspectRemoteSDPWithCandidatePolicy(body.SDP, prohibEPs, prohibIPs, candPolicy)
		if err != nil {
			if errors.Is(err, ErrProhibitedCandidate) || errors.Is(err, ErrProhibitedEndpoint) {
				c.prohibitedRejected.Add(1)
			}
			return err
		}

		// Existing session (e.g., ICE restart generation on an already-allowed session).
		if sessByID != nil {
			return sessByID.receiveVerifiedEnvelope(env, raw)
		}

		// Glare check: concurrent offers for the same peer pair (local user already chose Connect).
		if sessByPeer != nil {
			st := sessByPeer.State()
			if st == StateDiscovering || st == StateNegotiating {
				if c.PeerID() < env.From {
					return nil
				}
				c.mu.Lock()
				delete(c.sessionsByID, sessByPeer.SessionID())
				c.closedSessionIDs[sessByPeer.SessionID()] = time.Now()
				c.sessionsByID[env.SessionID] = sessByPeer
				c.mu.Unlock()
				return sessByPeer.adoptWinningRemoteOffer(env, raw, senderPub)
			}
		}

		if env.Seq != 0 {
			return ErrReplayedSignaling
		}

		// Explicit user Allow/Deny/Blacklist consent core: fail closed if no ConsentHandler is set.
		if c.cfg.Consent == nil {
			c.sendImmediateClose(env.From, env.SessionID, env.Generation, "user_denied")
			return ErrUserDenied
		}

		vip, err := identity.VirtualIPv4InPrefix(env.From, c.effectiveVirtualCIDR())
		if err != nil {
			return err
		}
		req := &IncomingRequest{
			PeerID:           env.From,
			PublicKey:        senderPub,
			Algorithm:        senderPub.Algorithm,
			VirtualIP:        vip,
			DisplayName:      known.DisplayName,
			ChannelID:        known.ChannelID,
			DTLSFingerprints: slices.Clone(info.SHA256Fingerprints),
			SessionID:        env.SessionID,
		}

		sess := newSession(c, env.From, senderPub, env.SessionID, false)
		sess.mu.Lock()
		sess.awaitingConsent = true
		sess.mu.Unlock()

		c.mu.Lock()
		c.sessionsByID[env.SessionID] = sess
		c.mu.Unlock()

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.processIncomingConsent(sess, env, raw, req)
		}()
		return nil
	}

	if sessByID == nil || sessByID.remotePeerID != env.From {
		return ErrReplayedSignaling
	}
	sessByID.setRemotePublicKey(senderPub)
	return sessByID.receiveVerifiedEnvelope(env, raw)
}

func (c *Client) processIncomingConsent(sess *Session, offerEnv *protocol.SignalEnvelope, rawOffer []byte, req *IncomingRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.ConsentTimeout)
	defer cancel()

	go func() {
		select {
		case <-c.stopCh:
			cancel()
		case <-sess.closedCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	decision := c.cfg.Consent.AuthorizeIncoming(ctx, req)
	if ctx.Err() != nil && decision == ConsentAllow {
		decision = ConsentDeny
	}

	switch decision {
	case ConsentAllow:
		if c.blacklist.Contains(req.PeerID) {
			c.sendImmediateClose(req.PeerID, offerEnv.SessionID, offerEnv.Generation, "blacklisted")
			sess.failClosed("blacklisted", ErrPeerBlacklisted)
			return
		}
		var superseded *Session
		c.mu.Lock()
		if old := c.sessionsByPeer[req.PeerID]; old != nil && old != sess {
			delete(c.sessionsByID, old.SessionID())
			c.closedSessionIDs[old.SessionID()] = time.Now()
			superseded = old
		}
		c.sessionsByPeer[req.PeerID] = sess
		c.mu.Unlock()
		if superseded != nil {
			superseded.failClosed("superseded_by_new_offer", ErrSessionClosed)
		}

		sess.mu.Lock()
		sess.awaitingConsent = false
		queued := slices.Clone(sess.preConsentQueue)
		sess.preConsentQueue = nil
		sess.mu.Unlock()

		if err := sess.receiveVerifiedEnvelope(offerEnv, rawOffer); err != nil {
			c.removeSession(sess, true)
			return
		}
		for _, item := range queued {
			_ = sess.receiveVerifiedEnvelope(item.env, item.raw)
		}

	case ConsentBlacklist:
		_ = c.Blacklist(req.PeerID)
		c.sendImmediateClose(req.PeerID, offerEnv.SessionID, offerEnv.Generation, "blacklisted")
		sess.failClosed("blacklisted", ErrPeerBlacklisted)

	default:
		c.sendImmediateClose(req.PeerID, offerEnv.SessionID, offerEnv.Generation, "user_denied")
		sess.failClosed("user_denied", ErrUserDenied)
	}
}

// Connect explicitly initiates a WebRTC session to targetPeerID and blocks until
// StateConnected is reached, the remote user denies/blacklists, or timeout expires.
func (c *Client) Connect(ctx context.Context, targetPeerID string) (*Session, error) {
	if err := identity.ValidatePeerID(targetPeerID); err != nil {
		return nil, err
	}
	if targetPeerID == c.PeerID() {
		return nil, errors.New("peer: cannot connect to self")
	}
	if c.blacklist.Contains(targetPeerID) {
		return nil, ErrPeerBlacklisted
	}
	if !c.wsOnline.Load() {
		return nil, ErrHubDisconnected
	}

	sessionID, err := protocol.NewSessionID()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	var knownPub identity.PublicKey
	if kp, ok := c.knownPeers[targetPeerID]; ok {
		knownPub = kp.PublicKey
	}
	if existing, ok := c.sessionsByPeer[targetPeerID]; ok {
		st := existing.State()
		if st == StateNegotiating || st == StateAuthenticating || st == StateConnected {
			c.mu.Unlock()
			deadlineCtx, cancel := context.WithTimeout(ctx, c.cfg.OfferToConnectedTimeout)
			defer cancel()
			return existing.waitConnected(deadlineCtx)
		}
	}
	sess := newSession(c, targetPeerID, knownPub, sessionID, true)
	c.sessionsByPeer[targetPeerID] = sess
	c.sessionsByID[sessionID] = sess
	c.mu.Unlock()

	sess.setState(StateDiscovering, "")

	deadlineCtx, cancel := context.WithTimeout(ctx, c.cfg.OfferToConnectedTimeout)
	defer cancel()

	if err := sess.startAsOfferer(deadlineCtx, 0); err != nil {
		if sess.State() != StateNegotiating && sess.State() != StateAuthenticating && sess.State() != StateConnected {
			c.removeSession(sess, true)
			return nil, err
		}
	}

	return sess.waitConnected(deadlineCtx)
}

func (c *Client) removeSession(sess *Session, markClosed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur := c.sessionsByID[sess.sessionID]; cur == sess {
		delete(c.sessionsByID, sess.sessionID)
	}
	if sess.remotePeerID != "" {
		if cur := c.sessionsByPeer[sess.remotePeerID]; cur == sess {
			delete(c.sessionsByPeer, sess.remotePeerID)
		}
	}
	if markClosed && sess.sessionID != "" {
		c.closedSessionIDs[sess.sessionID] = time.Now()
	}
}

// ProbeSTUNS verifies reachability and server certificate trust of the configured encrypted
// STUNS/TURNS server over DTLS 1.3 / UDP by default, or TLS 1.3 / TCP when TCPOnly is set.
func (c *Client) ProbeSTUNS(ctx context.Context) (*stun.XORMappedAddress, error) {
	c.iceMu.RLock()
	servers := slices.Clone(c.resolvedICE)
	c.iceMu.RUnlock()

	var target *stun.URI
	for _, srv := range servers {
		if srv.URI == nil || !srv.URI.IsSecure() {
			continue
		}
		if c.cfg.TCPOnly {
			if srv.URI.Proto == stun.ProtoTypeTCP {
				target = srv.URI
				break
			}
			continue
		}
		if srv.URI.Proto == stun.ProtoTypeUDP {
			target = srv.URI
			break
		}
		if target == nil {
			target = srv.URI
		}
	}
	if target == nil {
		if c.cfg.TCPOnly {
			return nil, errors.New("peer: no TLS/TCP stuns: or turns: server configured")
		}
		return nil, errors.New("peer: no DTLS/UDP stuns: or turns: server configured")
	}
	if c.cfg.TCPOnly || target.Proto == stun.ProtoTypeTCP {
		return probeSTUNSOverTLS13TCP(ctx, target, c.cfg.TLSConfig)
	}
	c.mu.Lock()
	vnet := c.vnet
	c.mu.Unlock()
	return probeSTUNSOverDTLS13(ctx, target, vnet, c.cfg.TLSConfig, c.cfg.PionLoggerFactory)
}

func (c *Client) buildWebRTCAPI() (*webrtc.API, error) {
	se := webrtc.SettingEngine{}

	minVer := dtlsProtocol.Version1_3
	maxVer := dtlsProtocol.Version1_3
	if c.cfg.OverrideDTLSMinVersion != 0 {
		minVer = c.cfg.OverrideDTLSMinVersion
	}
	if c.cfg.OverrideDTLSMaxVersion != 0 {
		maxVer = c.cfg.OverrideDTLSMaxVersion
	}
	se.SetDTLSMinVersion(minVer)
	se.SetDTLSMaxVersion(maxVer)
	se.SetDTLSReplayProtectionWindow(64)
	se.DisableCertificateFingerprintVerification(false)
	se.SetSCTPMaxMessageSize(MaxApplicationMessageBytes)
	se.SetNetworkTypes(c.cfg.NetworkTypes)
	se.SetIncludeLoopbackCandidate(c.cfg.IncludeLoopback)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	if c.cfg.PionLoggerFactory != nil {
		se.LoggerFactory = c.cfg.PionLoggerFactory
	}

	if c.cfg.ICEDisconnectedTimeout > 0 || c.cfg.ICEFailedTimeout > 0 || c.cfg.ICEKeepaliveInterval > 0 {
		disc := c.cfg.ICEDisconnectedTimeout
		if disc <= 0 {
			disc = 5 * time.Second
		}
		fail := c.cfg.ICEFailedTimeout
		if fail <= 0 {
			fail = 15 * time.Second
		}
		ka := c.cfg.ICEKeepaliveInterval
		if ka <= 0 {
			ka = 2 * time.Second
		}
		se.SetICETimeouts(disc, fail, ka)
	}

	c.mu.Lock()
	vnet := c.vnet
	c.mu.Unlock()

	c.iceMu.RLock()
	dtlsTargets := make(map[string]string, len(c.dtlsUDPTargets))
	for k, v := range c.dtlsUDPTargets {
		dtlsTargets[k] = v
	}
	tlsTargets := make(map[string]string, len(c.tlsTCPTargets))
	for k, v := range c.tlsTCPTargets {
		tlsTargets[k] = v
	}
	prohibitedIPs := append([]net.IP(nil), c.prohibitedIPs...)
	c.iceMu.RUnlock()

	switch {
	case c.cfg.TCPOnly:
		se.SetICETCPMux(c.tcpMux)
	case len(dtlsTargets) > 0:
		dtlsNet, err := newDTLS13TransportNet(vnet, dtlsTargets, c.cfg.TLSConfig, c.cfg.PionLoggerFactory)
		if err != nil {
			return nil, err
		}
		se.SetNet(dtlsNet)
	case vnet != nil:
		se.SetNet(vnet)
	}

	if !c.cfg.TCPOnly && len(tlsTargets) > 0 {
		se.SetICEProxyDialer(&turnTCPProxyDialer{
			tlsHosts: tlsTargets,
			tlsCfg:   c.cfg.TLSConfig,
		})
	}

	if len(prohibitedIPs) > 0 {
		se.SetRemoteIPFilter(func(ip net.IP) bool {
			for _, bip := range prohibitedIPs {
				if bip.Equal(ip) {
					return false
				}
			}
			return true
		})
	}

	return webrtc.NewAPI(webrtc.WithSettingEngine(se)), nil
}

type queuedEnvelope struct {
	env *protocol.SignalEnvelope
	raw []byte
}

// Session represents a user-authorized, end-to-end DTLS 1.3 WebRTC connection with one remote peer.
type Session struct {
	client       *Client
	remotePeerID string

	sendSignalMu       sync.Mutex
	mu                 sync.Mutex
	remotePub          identity.PublicKey
	remoteVIP          netip.Addr
	awaitingConsent    bool
	preConsentQueue    []queuedEnvelope
	closed             bool
	sessionID          string
	isInitiator        bool
	generation         uint32
	localSeq           uint64
	localICEUfrag      string
	localDescSent      bool
	pendingLocalCands  []protocol.CandidateBody
	pendingLocalEnd    *protocol.EndOfCandidatesBody
	nextRemoteSeq      uint64
	seenRemoteSeqHash  map[uint64][32]byte
	seenCandidateAttrs map[string]struct{}
	remoteCandCount    int
	pendingOutOfOrder  map[uint64]queuedEnvelope
	remoteSDPInstalled bool
	bufferedCandidates []protocol.CandidateBody
	expectedSHA256FPs  []string
	verifiedRemoteFP   string
	negotiatedMaxMsg   int

	pc          *webrtc.PeerConnection
	dataCh      *managedChannel
	packetCh    *managedChannel
	dataReady   bool
	dtlsReady   bool
	pairReady   bool
	restartUsed int
	restarting  bool
	notifiedApp bool

	state        ConnectionState
	failureCode  string
	failureErr   error
	pathVerified atomic.Bool

	connectedCh chan struct{}
	closedCh    chan struct{}

	recvDataCh   chan []byte
	recvPacketCh chan []byte
	stateHooks   []func(ConnectionState)
}

func newSession(client *Client, remotePeerID string, remotePub identity.PublicKey, sessionID string, initiator bool) *Session {
	cidr := identity.DefaultVirtualCIDR()
	if client != nil {
		cidr = client.effectiveVirtualCIDR()
	}
	vip, _ := identity.VirtualIPv4InPrefix(remotePeerID, cidr)
	s := &Session{
		client:             client,
		remotePeerID:       remotePeerID,
		remotePub:          remotePub,
		remoteVIP:          vip,
		sessionID:          sessionID,
		isInitiator:        initiator,
		seenRemoteSeqHash:  make(map[uint64][32]byte),
		seenCandidateAttrs: make(map[string]struct{}),
		pendingOutOfOrder:  make(map[uint64]queuedEnvelope),
		negotiatedMaxMsg:   MaxApplicationMessageBytes,
		state:              StateDisconnected,
		connectedCh:        make(chan struct{}),
		closedCh:           make(chan struct{}),
		recvDataCh:         make(chan []byte, 256),
		recvPacketCh:       make(chan []byte, 256),
	}
	s.dataCh = newManagedChannel(ChannelLabelDataV1, MaxApplicationMessageBytes, client.cfg.MaxQueueBytes, func(b []byte) {
		select {
		case s.recvDataCh <- b:
		case <-s.closedCh:
		}
	})
	s.packetCh = newManagedChannel(ChannelLabelPacketV1, MaxApplicationMessageBytes, client.cfg.MaxQueueBytes, func(b []byte) {
		select {
		case s.recvPacketCh <- b:
		case <-s.closedCh:
		}
	})
	return s
}

func (s *Session) setRemotePublicKey(pub identity.PublicKey) {
	if pub.IsZero() {
		return
	}
	s.mu.Lock()
	if s.remotePub.IsZero() {
		s.remotePub = pub
	}
	s.mu.Unlock()
}

// SessionID returns the active 128-bit base64url negotiation session ID.
func (s *Session) SessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

// RemotePeerID returns the authenticated remote peer_id.
func (s *Session) RemotePeerID() string {
	return s.remotePeerID
}

// RemoteVirtualIP returns the deterministic RFC 6598 TUN IPv4 address of the remote peer.
func (s *Session) RemoteVirtualIP() netip.Addr {
	return s.remoteVIP
}

// State returns the current ConnectionState.
func (s *Session) State() ConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Closed returns a channel closed when the session terminates.
func (s *Session) Closed() <-chan struct{} {
	return s.closedCh
}

// IsPathVerified reports whether DTLS 1.3, certificate fingerprint, ICE pair,
// and data/v1 DataChannel are all currently verified and active.
func (s *Session) IsPathVerified() bool {
	return s.pathVerified.Load()
}

// OnStateChange registers a callback invoked on state machine transitions.
func (s *Session) OnStateChange(fn func(ConnectionState)) {
	s.mu.Lock()
	s.stateHooks = append(s.stateHooks, fn)
	s.mu.Unlock()
}

// Send transmits an ordered, reliable binary message over "data/v1" (<= 16 KiB).
func (s *Session) Send(ctx context.Context, payload []byte) error {
	st := s.State()
	if st == StateFailed || st == StateDisconnected {
		return ErrSessionClosed
	}
	return s.dataCh.enqueue(ctx, payload)
}

// HasPacketChannel reports whether the unordered "packet/v1" channel is bound.
func (s *Session) HasPacketChannel() bool {
	return s.packetCh.isBound()
}

// SendPacket transmits an unordered, non-retransmitted datagram over "packet/v1".
func (s *Session) SendPacket(ctx context.Context, payload []byte) error {
	st := s.State()
	if st == StateFailed || st == StateDisconnected {
		return ErrSessionClosed
	}
	return s.packetCh.enqueue(ctx, payload)
}

// Messages returns the receive channel for verified "data/v1" payloads.
func (s *Session) Messages() <-chan []byte {
	return s.recvDataCh
}

// Packets returns the receive channel for verified "packet/v1" datagram payloads.
func (s *Session) Packets() <-chan []byte {
	return s.recvPacketCh
}

// Diagnostics returns an observability snapshot of transport security and ICE metrics.
func (s *Session) Diagnostics() SessionDiagnostics {
	s.mu.Lock()
	diag := SessionDiagnostics{
		RemotePeerID:     s.remotePeerID,
		RemoteVirtualIP:  s.remoteVIP.String(),
		SessionID:        s.sessionID,
		Generation:       s.generation,
		State:            s.state,
		RemoteCertSHA256: s.verifiedRemoteFP,
		FailureCode:      s.failureCode,
	}
	pc := s.pc
	s.mu.Unlock()

	if pc != nil && pc.SCTP() != nil && pc.SCTP().Transport() != nil {
		dtlsT := pc.SCTP().Transport()
		tStats := dtlsT.Stats()
		diag.DTLSVersion = tStats.TLSVersion
		diag.DTLSCipher = tStats.DTLSCipher
		diag.BytesSent = tStats.BytesSent
		diag.BytesReceived = tStats.BytesReceived

		if iceT := dtlsT.ICETransport(); iceT != nil {
			if pair, err := iceT.GetSelectedCandidatePair(); err == nil && pair != nil {
				if pair.Local != nil {
					diag.LocalCandidateType = pair.Local.Typ.String()
				}
				if pair.Remote != nil {
					diag.RemoteCandidateType = pair.Remote.Typ.String()
				}
				diag.SelectedPair = pair.String()
			}
			if pStats, ok := iceT.GetSelectedCandidatePairStats(); ok {
				diag.RTTSeconds = pStats.CurrentRoundTripTime
			}
		}
	}
	return diag
}

// Close gracefully terminates the session and notifies the remote peer if WSS is available.
func (s *Session) Close() error {
	return s.CloseWithReason("normal_close")
}

// CloseWithReason terminates the session with a bounded close reason code.
func (s *Session) CloseWithReason(reason string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pc := s.pc
	s.pc = nil
	sid := s.sessionID
	gen := s.generation
	s.pathVerified.Store(false)
	s.state = StateDisconnected
	hooks := slices.Clone(s.stateHooks)
	s.mu.Unlock()

	s.dataCh.close()
	s.packetCh.close()

	if s.remotePeerID != "" && sid != "" && s.client.wsOnline.Load() {
		_ = s.sendSignedEnvelope(context.Background(), gen, protocol.TypeClose, protocol.CloseBody{Reason: reason})
	}

	if pc != nil {
		_ = pc.Close()
	}
	s.closeSignalOnce()
	s.client.removeSession(s, true)
	for _, fn := range hooks {
		fn(StateDisconnected)
	}
	if s.client.cfg.OnSessionClosed != nil {
		go s.client.cfg.OnSessionClosed(s.remotePeerID, reason)
	}
	return nil
}

func (s *Session) closeSignalOnce() {
	select {
	case <-s.closedCh:
	default:
		close(s.closedCh)
	}
}

func (s *Session) waitConnected(ctx context.Context) (*Session, error) {
	select {
	case <-s.connectedCh:
		return s, nil
	case <-s.closedCh:
		s.mu.Lock()
		err := s.failureErr
		s.mu.Unlock()
		if err == nil {
			err = ErrSessionClosed
		}
		return nil, err
	case <-ctx.Done():
		s.failClosed("connect_timeout", ErrConnectTimeout)
		return nil, ErrConnectTimeout
	}
}

func (s *Session) setState(next ConnectionState, failCode string) {
	s.mu.Lock()
	if s.state == next {
		s.mu.Unlock()
		return
	}
	s.state = next
	if failCode != "" {
		s.failureCode = failCode
	}
	hooks := slices.Clone(s.stateHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn(next)
	}
}

func (s *Session) failClosed(code string, cause error) {
	s.mu.Lock()
	if s.closed || s.state == StateFailed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.pathVerified.Store(false)
	s.state = StateFailed
	s.failureCode = code
	s.failureErr = cause
	pc := s.pc
	s.pc = nil
	hooks := slices.Clone(s.stateHooks)
	s.mu.Unlock()

	s.dataCh.setPathAllowed(false)
	s.packetCh.setPathAllowed(false)
	s.dataCh.close()
	s.packetCh.close()
	if pc != nil {
		_ = pc.Close()
	}
	s.closeSignalOnce()
	s.client.removeSession(s, true)
	for _, fn := range hooks {
		fn(StateFailed)
	}
	if s.client.cfg.OnSessionClosed != nil {
		go s.client.cfg.OnSessionClosed(s.remotePeerID, code)
	}
}

func (s *Session) resetGenerationLocked(gen uint32) *webrtc.PeerConnection {
	oldPC := s.pc
	s.pc = nil
	s.generation = gen
	s.restarting = false
	s.localSeq = 0
	s.localICEUfrag = ""
	s.localDescSent = false
	s.pendingLocalCands = nil
	s.pendingLocalEnd = nil
	s.nextRemoteSeq = 0
	s.seenRemoteSeqHash = make(map[uint64][32]byte)
	s.seenCandidateAttrs = make(map[string]struct{})
	s.remoteCandCount = 0
	s.pendingOutOfOrder = make(map[uint64]queuedEnvelope)
	s.remoteSDPInstalled = false
	s.bufferedCandidates = nil
	s.expectedSHA256FPs = nil
	s.verifiedRemoteFP = ""
	s.dataReady = false
	s.dtlsReady = false
	s.pairReady = false
	s.pathVerified.Store(false)
	s.dataCh.setPathAllowed(false)
	s.packetCh.setPathAllowed(false)
	return oldPC
}

func (s *Session) newPeerConnectionLocked(gen uint32, offerer bool) (*webrtc.PeerConnection, error) {
	api, err := s.client.buildWebRTCAPI()
	if err != nil {
		return nil, err
	}
	s.client.iceMu.RLock()
	iceSrvs := slices.Clone(s.client.webrtcICEServers)
	s.client.iceMu.RUnlock()

	pcCfg := webrtc.Configuration{
		ICEServers:         iceSrvs,
		ICETransportPolicy: s.client.cfg.ICETransportPolicy,
	}
	if s.client.cfg.DTLSCertAlgorithm != "" {
		cert, certErr := generateEphemeralDTLSCertificate(s.client.cfg.DTLSCertAlgorithm, s.client.cfg.DTLSRSABits)
		if certErr != nil {
			return nil, certErr
		}
		pcCfg.Certificates = []webrtc.Certificate{cert}
	}
	pc, err := api.NewPeerConnection(pcCfg)
	if err != nil {
		return nil, err
	}
	s.pc = pc

	timeout := s.client.cfg.OfferToConnectedTimeout
	go func(targetGen uint32, targetPC *webrtc.PeerConnection) {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-s.closedCh:
			return
		case <-timer.C:
			s.mu.Lock()
			stillPending := s.pc == targetPC && s.generation == targetGen && s.state != StateConnected
			s.mu.Unlock()
			if stillPending {
				s.failClosed("negotiation_timeout", ErrConnectTimeout)
			}
		}
	}(gen, pc)

	pc.OnICECandidate(func(cand *webrtc.ICECandidate) {
		s.onLocalICECandidate(gen, pc, cand)
	})

	iceT := pc.SCTP().Transport().ICETransport()
	iceT.OnSelectedCandidatePairChange(func(pair *webrtc.ICECandidatePair) {
		s.onSelectedPairChange(gen, pc, pair)
	})
	iceT.OnConnectionStateChange(func(st webrtc.ICETransportState) {
		s.onICEStateChange(gen, pc, st)
	})

	dtlsT := pc.SCTP().Transport()
	dtlsT.OnStateChange(func(st webrtc.DTLSTransportState) {
		s.onDTLSStateChange(gen, pc, st)
	})

	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed {
			s.onTransportLost(gen, pc, "peer_connection_failed")
		}
	})

	if offerer {
		ordered := true
		dc, err := pc.CreateDataChannel(ChannelLabelDataV1, &webrtc.DataChannelInit{
			Ordered: &ordered,
		})
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
		s.bindDataV1(gen, pc, dc)

		if s.client.cfg.EnablePacketChannel {
			unordered := false
			zero := uint16(0)
			pdc, err := pc.CreateDataChannel(ChannelLabelPacketV1, &webrtc.DataChannelInit{
				Ordered:        &unordered,
				MaxRetransmits: &zero,
			})
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			s.packetCh.bindDataChannel(pdc, s.negotiatedMaxMsg)
		}
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			s.onIncomingDataChannel(gen, pc, dc)
		})
	}

	return pc, nil
}

func (s *Session) bindDataV1(gen uint32, pc *webrtc.PeerConnection, dc *webrtc.DataChannel) {
	s.dataCh.bindDataChannel(dc, s.negotiatedMaxMsg)
	if dc.ReadyState() == webrtc.DataChannelStateOpen {
		s.markDataChannelOpen(gen, pc)
	}
	dc.OnOpen(func() {
		s.dataCh.mu.Lock()
		if s.dataCh.dc == dc {
			s.dataCh.dcOpen = true
		}
		s.dataCh.mu.Unlock()
		s.dataCh.signal()
		s.markDataChannelOpen(gen, pc)
	})
}

func (s *Session) onIncomingDataChannel(gen uint32, pc *webrtc.PeerConnection, dc *webrtc.DataChannel) {
	s.mu.Lock()
	if s.pc != pc || s.generation != gen {
		s.mu.Unlock()
		_ = dc.Close()
		return
	}
	maxMsg := s.negotiatedMaxMsg
	s.mu.Unlock()

	switch dc.Label() {
	case ChannelLabelDataV1:
		if !dc.Ordered() || dc.MaxRetransmits() != nil || dc.MaxPacketLifeTime() != nil || dc.Negotiated() {
			_ = dc.Close()
			s.failClosed("invalid_datachannel_settings", ErrInvalidRemoteSDP)
			return
		}
		s.bindDataV1(gen, pc, dc)

	case ChannelLabelPacketV1:
		if dc.Ordered() || dc.MaxRetransmits() == nil || *dc.MaxRetransmits() != 0 || dc.MaxPacketLifeTime() != nil || dc.Negotiated() {
			_ = dc.Close()
			s.failClosed("invalid_datachannel_settings", ErrInvalidRemoteSDP)
			return
		}
		s.packetCh.bindDataChannel(dc, maxMsg)

	default:
		_ = dc.Close()
	}
}

func (s *Session) startAsOfferer(ctx context.Context, gen uint32) error {
	s.mu.Lock()
	oldPC := s.resetGenerationLocked(gen)
	s.isInitiator = true
	pc, err := s.newPeerConnectionLocked(gen, true)
	s.mu.Unlock()
	if oldPC != nil {
		_ = oldPC.Close()
	}
	if err != nil {
		return err
	}

	s.setState(StateNegotiating, "")

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.localICEUfrag = extractICEUfragFromSDP(offer.SDP)
	s.mu.Unlock()
	if err := pc.SetLocalDescription(offer); err != nil {
		return err
	}

	if err := s.sendSignedEnvelope(ctx, gen, protocol.TypeOffer, protocol.SDPBody{SDP: offer.SDP}); err != nil {
		return err
	}
	s.flushLocalCandidates(gen)
	return nil
}

func (s *Session) adoptWinningRemoteOffer(env *protocol.SignalEnvelope, raw []byte, remotePub identity.PublicKey) error {
	s.mu.Lock()
	oldPC := s.resetGenerationLocked(env.Generation)
	s.sessionID = env.SessionID
	s.remotePub = remotePub
	s.isInitiator = false
	s.mu.Unlock()
	if oldPC != nil {
		_ = oldPC.Close()
	}
	return s.receiveVerifiedEnvelope(env, raw)
}

func (s *Session) receiveVerifiedEnvelope(env *protocol.SignalEnvelope, raw []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	if s.awaitingConsent {
		if env.Type == protocol.TypeClose {
			s.mu.Unlock()
			s.failClosed("remote_closed", ErrSessionClosed)
			return nil
		}
		if len(s.preConsentQueue) >= s.client.cfg.MaxCandidatesPerGen {
			s.mu.Unlock()
			return ErrCandidateLimit
		}
		s.preConsentQueue = append(s.preConsentQueue, queuedEnvelope{env: env, raw: append([]byte(nil), raw...)})
		s.mu.Unlock()
		return nil
	}

	if env.Generation < s.generation {
		s.mu.Unlock()
		return ErrStaleGeneration
	}

	if env.Generation > s.generation {
		if env.Type != protocol.TypeOffer || env.Seq != 0 {
			s.mu.Unlock()
			return ErrStaleGeneration
		}
		oldPC := s.resetGenerationLocked(env.Generation)
		s.isInitiator = false
		s.mu.Unlock()
		if oldPC != nil {
			_ = oldPC.Close()
		}
		s.setState(StateReconnecting, "")
		s.mu.Lock()
	}

	payloadHash := sha256.Sum256(raw)
	if prevHash, seen := s.seenRemoteSeqHash[env.Seq]; seen {
		s.mu.Unlock()
		if env.Type == protocol.TypeCandidate || env.Type == protocol.TypeEndOfCandidates {
			if prevHash == payloadHash {
				return nil
			}
		}
		return ErrReplayedSignaling
	}
	if env.Seq < s.nextRemoteSeq {
		s.mu.Unlock()
		return ErrReplayedSignaling
	}
	if env.Seq > s.nextRemoteSeq {
		if len(s.pendingOutOfOrder) >= s.client.cfg.MaxCandidatesPerGen {
			s.mu.Unlock()
			return ErrCandidateLimit
		}
		s.pendingOutOfOrder[env.Seq] = queuedEnvelope{env: env, raw: append([]byte(nil), raw...)}
		s.mu.Unlock()
		return nil
	}

	queue := []queuedEnvelope{{env: env, raw: raw}}
	s.seenRemoteSeqHash[env.Seq] = payloadHash
	s.nextRemoteSeq++
	for {
		nxt, ok := s.pendingOutOfOrder[s.nextRemoteSeq]
		if !ok {
			break
		}
		delete(s.pendingOutOfOrder, s.nextRemoteSeq)
		s.seenRemoteSeqHash[s.nextRemoteSeq] = sha256.Sum256(nxt.raw)
		s.nextRemoteSeq++
		queue = append(queue, nxt)
	}
	s.mu.Unlock()

	for _, item := range queue {
		if err := s.applyOrderedEnvelope(item.env); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) applyOrderedEnvelope(env *protocol.SignalEnvelope) error {
	candPolicy, prohibEPs, prohibIPs := s.client.candidatePolicySnapshot()

	switch env.Type {
	case protocol.TypeOffer:
		var body protocol.SDPBody
		if err := jcs.UnmarshalStrict(env.Body, &body); err != nil {
			return err
		}
		info, err := ValidateAndInspectRemoteSDPWithCandidatePolicy(body.SDP, prohibEPs, prohibIPs, candPolicy)
		if err != nil {
			if errors.Is(err, ErrProhibitedCandidate) || errors.Is(err, ErrProhibitedEndpoint) {
				s.client.prohibitedRejected.Add(1)
			}
			s.failClosed("prohibited_or_invalid_offer_sdp", err)
			return err
		}

		s.mu.Lock()
		oldPC := s.pc
		s.pc = nil
		s.expectedSHA256FPs = info.SHA256Fingerprints
		s.negotiatedMaxMsg = info.MaxMessageSize
		pc, err := s.newPeerConnectionLocked(env.Generation, false)
		s.mu.Unlock()
		if oldPC != nil {
			_ = oldPC.Close()
		}
		if err != nil {
			s.failClosed("pc_create_failed", err)
			return err
		}

		s.setState(StateNegotiating, "")
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  body.SDP,
		}); err != nil {
			s.failClosed("set_remote_offer_failed", err)
			return err
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			s.failClosed("create_answer_failed", err)
			return err
		}
		s.mu.Lock()
		s.localICEUfrag = extractICEUfragFromSDP(answer.SDP)
		s.mu.Unlock()
		if err := pc.SetLocalDescription(answer); err != nil {
			s.failClosed("set_local_answer_failed", err)
			return err
		}
		if err := s.flushBufferedCandidates(env.Generation, pc); err != nil {
			return err
		}
		if err := s.sendSignedEnvelope(context.Background(), env.Generation, protocol.TypeAnswer, protocol.SDPBody{SDP: answer.SDP}); err != nil {
			s.failClosed("send_answer_failed", err)
			return err
		}
		s.flushLocalCandidates(env.Generation)
		return nil

	case protocol.TypeAnswer:
		var body protocol.SDPBody
		if err := jcs.UnmarshalStrict(env.Body, &body); err != nil {
			return err
		}
		info, err := ValidateAndInspectRemoteSDPWithCandidatePolicy(body.SDP, prohibEPs, prohibIPs, candPolicy)
		if err != nil {
			if errors.Is(err, ErrProhibitedCandidate) || errors.Is(err, ErrProhibitedEndpoint) {
				s.client.prohibitedRejected.Add(1)
			}
			s.failClosed("prohibited_or_invalid_answer_sdp", err)
			return err
		}

		s.mu.Lock()
		pc := s.pc
		if pc == nil || s.generation != env.Generation {
			s.mu.Unlock()
			return ErrStaleGeneration
		}
		s.expectedSHA256FPs = info.SHA256Fingerprints
		s.negotiatedMaxMsg = info.MaxMessageSize
		s.mu.Unlock()

		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeAnswer,
			SDP:  body.SDP,
		}); err != nil {
			s.failClosed("set_remote_answer_failed", err)
			return err
		}
		return s.flushBufferedCandidates(env.Generation, pc)

	case protocol.TypeCandidate:
		var body protocol.CandidateBody
		if err := jcs.UnmarshalStrict(env.Body, &body); err != nil {
			return err
		}
		if err := ValidateTrickleCandidateWithCandidatePolicy(body, prohibEPs, prohibIPs, candPolicy); err != nil {
			s.client.prohibitedRejected.Add(1)
			return err
		}

		s.mu.Lock()
		if s.remoteCandCount >= s.client.cfg.MaxCandidatesPerGen {
			s.mu.Unlock()
			return ErrCandidateLimit
		}
		if _, dup := s.seenCandidateAttrs[body.Candidate]; dup {
			s.mu.Unlock()
			return nil
		}
		s.seenCandidateAttrs[body.Candidate] = struct{}{}
		s.remoteCandCount++

		if !s.remoteSDPInstalled || s.pc == nil {
			s.bufferedCandidates = append(s.bufferedCandidates, body)
			s.mu.Unlock()
			return nil
		}
		pc := s.pc
		s.mu.Unlock()

		return pc.AddICECandidate(webrtc.ICECandidateInit{
			Candidate:        body.Candidate,
			SDPMid:           body.SDPMid,
			SDPMLineIndex:    body.SDPMLineIndex,
			UsernameFragment: nonEmptyPtr(body.UsernameFragment),
		})

	case protocol.TypeEndOfCandidates:
		var body protocol.EndOfCandidatesBody
		return jcs.UnmarshalStrict(env.Body, &body)

	case protocol.TypeClose:
		var body protocol.CloseBody
		if err := jcs.UnmarshalStrict(env.Body, &body); err != nil {
			return err
		}
		switch body.Reason {
		case "user_denied":
			s.failClosed(body.Reason, ErrUserDenied)
			return nil
		case "blacklisted":
			s.failClosed(body.Reason, ErrPeerBlacklisted)
			return nil
		}

		s.mu.Lock()
		s.closed = true
		pc := s.pc
		s.pc = nil
		s.pathVerified.Store(false)
		s.state = StateDisconnected
		hooks := slices.Clone(s.stateHooks)
		s.mu.Unlock()

		s.dataCh.close()
		s.packetCh.close()
		if pc != nil {
			_ = pc.Close()
		}
		s.closeSignalOnce()
		s.client.removeSession(s, true)
		for _, fn := range hooks {
			fn(StateDisconnected)
		}
		if s.client.cfg.OnSessionClosed != nil {
			go s.client.cfg.OnSessionClosed(s.remotePeerID, body.Reason)
		}
		return nil
	}
	return nil
}

func (s *Session) flushBufferedCandidates(gen uint32, pc *webrtc.PeerConnection) error {
	s.mu.Lock()
	if s.pc != pc || s.generation != gen {
		s.mu.Unlock()
		return nil
	}
	s.remoteSDPInstalled = true
	buffered := append([]protocol.CandidateBody(nil), s.bufferedCandidates...)
	s.bufferedCandidates = nil
	s.mu.Unlock()

	for _, c := range buffered {
		if err := pc.AddICECandidate(webrtc.ICECandidateInit{
			Candidate:        c.Candidate,
			SDPMid:           c.SDPMid,
			SDPMLineIndex:    c.SDPMLineIndex,
			UsernameFragment: nonEmptyPtr(c.UsernameFragment),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) onLocalICECandidate(gen uint32, pc *webrtc.PeerConnection, cand *webrtc.ICECandidate) {
	if cand == nil {
		s.mu.Lock()
		if s.generation != gen || s.pc != pc {
			s.mu.Unlock()
			return
		}
		ufrag := s.localICEUfrag
		if ufrag == "" {
			ufrag = "0"
		}
		endBody := protocol.EndOfCandidatesBody{UsernameFragment: ufrag}
		if !s.localDescSent {
			s.pendingLocalEnd = &endBody
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		if s.client.wsOnline.Load() {
			_ = s.sendSignedEnvelope(context.Background(), gen, protocol.TypeEndOfCandidates, endBody)
		}
		return
	}

	candPolicy, _, _ := s.client.candidatePolicySnapshot()
	wantProto := webrtc.ICEProtocolUDP
	if candPolicy.TCPOnly {
		wantProto = webrtc.ICEProtocolTCP
	}
	if !isAllowedWebRTCCandidateType(cand.Typ, candPolicy.AllowRelay) || cand.Protocol != wantProto {
		return
	}
	initJSON := cand.ToJSON()

	s.mu.Lock()
	if s.generation != gen || s.pc != pc {
		s.mu.Unlock()
		return
	}
	ufrag := s.localICEUfrag
	if initJSON.UsernameFragment != nil && *initJSON.UsernameFragment != "" {
		ufrag = *initJSON.UsernameFragment
	}
	cBody := protocol.CandidateBody{
		Candidate:        initJSON.Candidate,
		SDPMid:           initJSON.SDPMid,
		SDPMLineIndex:    initJSON.SDPMLineIndex,
		UsernameFragment: ufrag,
	}
	if !s.localDescSent {
		s.pendingLocalCands = append(s.pendingLocalCands, cBody)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if s.client.wsOnline.Load() {
		_ = s.sendSignedEnvelope(context.Background(), gen, protocol.TypeCandidate, cBody)
	}
}

func extractICEUfragFromSDP(rawSDP string) string {
	for line := range strings.SplitSeq(rawSDP, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "a=ice-ufrag:"); ok && after != "" {
			return after
		}
	}
	return "0"
}

func (s *Session) flushLocalCandidates(gen uint32) {
	s.mu.Lock()
	if s.generation != gen {
		s.mu.Unlock()
		return
	}
	s.localDescSent = true
	cands := slices.Clone(s.pendingLocalCands)
	s.pendingLocalCands = nil
	endBody := s.pendingLocalEnd
	s.pendingLocalEnd = nil
	s.mu.Unlock()

	if !s.client.wsOnline.Load() {
		return
	}
	for _, cb := range cands {
		_ = s.sendSignedEnvelope(context.Background(), gen, protocol.TypeCandidate, cb)
	}
	if endBody != nil {
		_ = s.sendSignedEnvelope(context.Background(), gen, protocol.TypeEndOfCandidates, *endBody)
	}
}

func (s *Session) sendSignedEnvelope(ctx context.Context, gen uint32, msgType string, body any) error {
	s.sendSignalMu.Lock()
	defer s.sendSignalMu.Unlock()

	s.mu.Lock()
	if s.generation != gen || s.remotePeerID == "" {
		s.mu.Unlock()
		return ErrStaleGeneration
	}
	seq := s.localSeq
	s.localSeq++
	sid := s.sessionID
	to := s.remotePeerID
	s.mu.Unlock()

	exp := time.Now().Add(s.client.cfg.SignalingTTL).Unix()
	_, raw, err := protocol.SignEnvelope(
		s.client.cfg.KeyPair,
		msgType,
		to,
		sid,
		gen,
		seq,
		exp,
		body,
	)
	if err != nil {
		return err
	}
	return s.client.sendWS(ctx, raw)
}

func (s *Session) onSelectedPairChange(gen uint32, pc *webrtc.PeerConnection, pair *webrtc.ICECandidatePair) {
	candPolicy, prohibEPs, prohibIPs := s.client.candidatePolicySnapshot()
	if err := ValidateSelectedPairWithCandidatePolicy(pair, prohibEPs, prohibIPs, candPolicy); err != nil {
		s.pathVerified.Store(false)
		s.dataCh.setPathAllowed(false)
		s.packetCh.setPathAllowed(false)
		s.client.prohibitedRejected.Add(1)
		s.failClosed("prohibited_selected_pair", err)
		return
	}

	s.mu.Lock()
	if s.pc != pc || s.generation != gen {
		s.mu.Unlock()
		return
	}
	s.pairReady = true
	if s.state == StateNegotiating {
		s.mu.Unlock()
		s.setState(StateAuthenticating, "")
	} else {
		s.mu.Unlock()
	}
	s.tryPromoteToConnected(gen, pc)
}

func (s *Session) onICEStateChange(gen uint32, pc *webrtc.PeerConnection, st webrtc.ICETransportState) {
	switch st {
	case webrtc.ICETransportStateConnected, webrtc.ICETransportStateCompleted:
		if pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair(); err == nil && pair != nil {
			s.onSelectedPairChange(gen, pc, pair)
		}
	case webrtc.ICETransportStateDisconnected:
		s.onTransportLost(gen, pc, "ice_disconnected")
	case webrtc.ICETransportStateFailed:
		s.onTransportLost(gen, pc, "ice_failed")
	}
}

func (s *Session) onDTLSStateChange(gen uint32, pc *webrtc.PeerConnection, st webrtc.DTLSTransportState) {
	switch st {
	case webrtc.DTLSTransportStateConnected:
		dtlsT := pc.SCTP().Transport()
		tStats := dtlsT.Stats()
		if !strings.EqualFold(tStats.TLSVersion, ExpectedDTLS13HexVersion) {
			s.failClosed("dtls_version_downgrade", ErrDTLSVersionDowngrade)
			return
		}

		s.mu.Lock()
		if s.pc != pc || s.generation != gen {
			s.mu.Unlock()
			return
		}
		expectedFPs := append([]string(nil), s.expectedSHA256FPs...)
		s.mu.Unlock()

		actualFP, err := VerifyRemoteCertSHA256(dtlsT.GetRemoteCertificate(), expectedFPs)
		if err != nil {
			s.failClosed("dtls_fingerprint_mismatch", err)
			return
		}

		s.mu.Lock()
		if s.pc == pc && s.generation == gen {
			s.verifiedRemoteFP = actualFP
			s.dtlsReady = true
		}
		s.mu.Unlock()
		s.tryPromoteToConnected(gen, pc)

	case webrtc.DTLSTransportStateFailed:
		s.failClosed("dtls_handshake_failed", errors.New("peer: DTLS transport failed"))
	}
}

func (s *Session) markDataChannelOpen(gen uint32, pc *webrtc.PeerConnection) {
	s.mu.Lock()
	if s.pc == pc && s.generation == gen {
		s.dataReady = true
	}
	s.mu.Unlock()
	s.tryPromoteToConnected(gen, pc)
}

func (s *Session) tryPromoteToConnected(gen uint32, pc *webrtc.PeerConnection) {
	candPolicy, prohibEPs, prohibIPs := s.client.candidatePolicySnapshot()
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || ValidateSelectedPairWithCandidatePolicy(pair, prohibEPs, prohibIPs, candPolicy) != nil {
		return
	}

	s.mu.Lock()
	if s.pc != pc || s.generation != gen || !s.pairReady || !s.dtlsReady || !s.dataReady {
		s.mu.Unlock()
		return
	}
	if s.state == StateFailed || s.state == StateDisconnected || s.restarting {
		s.mu.Unlock()
		return
	}
	firstConnect := !s.notifiedApp
	s.notifiedApp = true
	s.pathVerified.Store(true)
	prevState := s.state
	s.state = StateConnected
	hooks := slices.Clone(s.stateHooks)
	s.mu.Unlock()

	s.dataCh.setPathAllowed(true)
	s.packetCh.setPathAllowed(true)

	select {
	case <-s.connectedCh:
	default:
		close(s.connectedCh)
	}

	if prevState != StateConnected {
		for _, fn := range hooks {
			fn(StateConnected)
		}
	}
	if firstConnect && s.client.cfg.OnSession != nil {
		go s.client.cfg.OnSession(s)
	}
}

// RestartICE manually triggers a bounded signed ICE restart on an established session.
func (s *Session) RestartICE(ctx context.Context) error {
	s.mu.Lock()
	startGen := s.generation
	s.mu.Unlock()
	s.triggerNetworkChange()
	budget := s.client.cfg.OfferToConnectedTimeout + s.client.cfg.ICERestartBackoff*time.Duration(1<<max(0, s.client.cfg.MaxICERestarts))
	deadline, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		s.mu.Lock()
		st := s.state
		curGen := s.generation
		s.mu.Unlock()
		if curGen > startGen && st == StateConnected && s.IsPathVerified() {
			return nil
		}
		if st == StateFailed || st == StateDisconnected {
			return ErrRestartExhausted
		}
		select {
		case <-deadline.Done():
			s.failClosed("restart_timeout", ErrRestartExhausted)
			return ErrRestartExhausted
		case <-s.closedCh:
			return ErrRestartExhausted
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (s *Session) triggerNetworkChange() {
	s.mu.Lock()
	gen := s.generation
	pc := s.pc
	s.mu.Unlock()
	s.onTransportLost(gen, pc, "network_change")
}

func (s *Session) onTransportLost(gen uint32, pc *webrtc.PeerConnection, reason string) {
	s.mu.Lock()
	if s.pc != pc || s.generation != gen {
		s.mu.Unlock()
		return
	}
	if s.state != StateConnected && s.state != StateReconnecting {
		if reason == "ice_failed" || reason == "peer_connection_failed" {
			s.mu.Unlock()
			s.failClosed(reason, errors.New("peer: ICE negotiation failed"))
			return
		}
		s.mu.Unlock()
		return
	}

	s.pathVerified.Store(false)
	s.dataCh.setPathAllowed(false)
	s.packetCh.setPathAllowed(false)

	if s.restarting {
		s.mu.Unlock()
		return
	}
	if !s.client.wsOnline.Load() {
		if reason == "ice_failed" || reason == "peer_connection_failed" || reason == "network_change" {
			s.mu.Unlock()
			s.failClosed("hub_unavailable_for_restart", ErrHubDisconnected)
			return
		}
		s.mu.Unlock()
		return
	}

	shouldDriveOffer := (s.client.PeerID() < s.RemotePeerID()) || reason == "network_change"
	if !shouldDriveOffer {
		s.mu.Unlock()
		s.setState(StateReconnecting, "")
		return
	}

	if s.restartUsed >= s.client.cfg.MaxICERestarts {
		s.mu.Unlock()
		s.failClosed("restart_budget_exhausted", ErrRestartExhausted)
		return
	}
	s.restarting = true
	attempt := s.restartUsed
	s.restartUsed++
	nextGen := s.generation + 1
	s.mu.Unlock()

	s.setState(StateReconnecting, "")

	go func() {
		backoff := s.client.cfg.ICERestartBackoff * time.Duration(1<<attempt)
		timer := time.NewTimer(backoff)
		select {
		case <-s.closedCh:
			timer.Stop()
			return
		case <-timer.C:
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.client.cfg.OfferToConnectedTimeout)
		defer cancel()
		if err := s.startAsOfferer(ctx, nextGen); err != nil {
			s.failClosed("ice_restart_offer_failed", err)
		}
	}()
}

func nonEmptyPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// SortedFingerprints returns a deterministic sorted copy of fingerprint strings.
func SortedFingerprints(in []string) []string {
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	return cp
}
