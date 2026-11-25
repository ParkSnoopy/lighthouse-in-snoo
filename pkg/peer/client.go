package peer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

// Config configures an authenticated direct-only WebRTC peer client.
type Config struct {
	KeyPair    *identity.KeyPair
	Membership *identity.MembershipRecord
	Policy     identity.PolicyConfig

	SignalingURL  string // e.g. wss://hub.example.com/v1/signal
	HubOrigin     string // Optional explicit canonical origin; derived from SignalingURL if empty.
	TLSConfig     *tls.Config
	HTTPTransport http.RoundTripper // Optional custom transport (e.g. for custom dialer in tests).

	STUNServerURI       string               // Single UDP stun:host:port URI (Section 5.1).
	NetworkTypes        []webrtc.NetworkType // Defaults to [UDP4, UDP6].
	IncludeLoopback     bool
	VNet                transport.Net // Optional virtual network stack (pion/transport/v5/vnet).
	PionLoggerFactory   logging.LoggerFactory
	ProhibitedEndpoints []net.UDPAddr // Additional endpoints forbidden as data destinations.
	BlockHubHostIP      *bool         // Defaults to true when Hub IP is non-loopback and non-local.

	EnablePacketChannel     bool // Negotiate optional unordered packet/v1 DataChannel (Section 7).
	MaxQueueBytes           int
	OfferToConnectedTimeout time.Duration // Default 30s (Section 9).
	MaxICERestarts          int           // Default 2 (Section 9).
	ICERestartBackoff       time.Duration // Default 500ms base backoff.
	ICEDisconnectedTimeout  time.Duration // Optional override for Pion ICE disconnected timeout.
	ICEFailedTimeout        time.Duration // Optional override for Pion ICE failed timeout.
	ICEKeepaliveInterval    time.Duration // Optional override for Pion ICE keepalive interval.
	HeartbeatInterval       time.Duration // Default 20s (Section 9).
	SignalingTTL            time.Duration // Default 60s (Section 9).
	MaxClockSkew            time.Duration // Default 30s (Section 9).
	MaxCandidatesPerGen     int           // Default 128 (Section 9).

	// Strictly for T05 negative testing (simulating a non-conformant DTLS 1.2 peer).
	// Production callers MUST leave both zero (which enforces DTLS 1.3 min and max).
	OverrideDTLSMinVersion dtlsProtocol.Version
	OverrideDTLSMaxVersion dtlsProtocol.Version

	OnSession func(*Session)
	Logger    *slog.Logger
}

type lookupWaiter struct {
	res protocol.LookupResultMessage
	err error
}

// Client manages a peer's Ed25519 identity, authenticated WSS control-plane session,
// independent trust verification, and direct-only WebRTC PeerConnections.
type Client struct {
	cfg       Config
	hubOrigin string
	trust     *identity.TrustVerifier
	log       *slog.Logger

	prohibitedEndpoints []net.UDPAddr
	prohibitedIPs       []net.IP

	wsMu      sync.Mutex
	wsConn    *websocket.Conn
	wsOnline  atomic.Bool
	wsWriteMu sync.Mutex

	mu                 sync.Mutex
	vnet               transport.Net
	sessionsByPeer     map[string]*Session
	sessionsByID       map[string]*Session
	closedSessionIDs   map[string]time.Time
	pendingLookups     map[string][]chan lookupWaiter
	lastSignalRejected atomic.Uint64
	prohibitedRejected atomic.Uint64

	signalCh chan []byte
	stopCh   chan struct{}
	closed   atomic.Bool
	wg       sync.WaitGroup
}

// NewClient validates configuration and constructs a new peer Client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.KeyPair == nil {
		return nil, errors.New("peer: KeyPair is required")
	}
	if err := identity.ValidatePeerID(cfg.KeyPair.PeerID); err != nil {
		return nil, err
	}
	if err := ValidateSTUNServerURI(cfg.STUNServerURI); err != nil {
		return nil, err
	}
	for _, nt := range cfg.NetworkTypes {
		if nt != webrtc.NetworkTypeUDP4 && nt != webrtc.NetworkTypeUDP6 {
			return nil, fmt.Errorf("%w: non-UDP network type %s", ErrInvalidICEConfig, nt.String())
		}
	}
	if len(cfg.NetworkTypes) == 0 {
		cfg.NetworkTypes = []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6}
	}
	if cfg.OfferToConnectedTimeout <= 0 {
		cfg.OfferToConnectedTimeout = 30 * time.Second
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

	trust, err := identity.NewTrustVerifier(cfg.Policy, cfg.MaxClockSkew)
	if err != nil {
		return nil, err
	}

	prohibitedEPs, prohibitedIPs := deriveProhibitedHubTargets(cfg)

	c := &Client{
		cfg:                 cfg,
		hubOrigin:           origin,
		trust:               trust,
		log:                 cfg.Logger,
		prohibitedEndpoints: prohibitedEPs,
		prohibitedIPs:       prohibitedIPs,
		vnet:                cfg.VNet,
		sessionsByPeer:      make(map[string]*Session),
		sessionsByID:        make(map[string]*Session),
		closedSessionIDs:    make(map[string]time.Time),
		pendingLookups:      make(map[string][]chan lookupWaiter),
		signalCh:            make(chan []byte, 512),
		stopCh:              make(chan struct{}),
	}
	c.wg.Add(1)
	go c.signalWorkerLoop()
	return c, nil
}

func deriveProhibitedHubTargets(cfg Config) ([]net.UDPAddr, []net.IP) {
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
			blockIP := !isLocal(ip)
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
			blockIP := !isLocal(ip)
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
	if cfg.STUNServerURI != "" {
		if su, err := stun.ParseURI(cfg.STUNServerURI); err == nil {
			addEndpoint(su.Host, su.Port)
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

// PeerID returns this client's persistent Ed25519 peer_id.
func (c *Client) PeerID() string {
	return c.cfg.KeyPair.PeerID
}

// RejectedSignalCount returns how many invalid/replayed/tampered signaling envelopes were rejected.
func (c *Client) RejectedSignalCount() uint64 {
	return c.lastSignalRejected.Load()
}

// ProhibitedCandidateCount returns how many relay/non-UDP/hub-endpoint candidates were blocked.
func (c *Client) ProhibitedCandidateCount() uint64 {
	return c.prohibitedRejected.Load()
}

// ReloadPolicy atomically updates local trust and ACL rules and terminates any revoked peer sessions.
func (c *Client) ReloadPolicy(policy identity.PolicyConfig) error {
	if err := c.trust.Reload(policy); err != nil {
		return err
	}
	c.mu.Lock()
	var revokedSessions []*Session
	for pid, sess := range c.sessionsByPeer {
		if c.trust.IsRevoked(pid) {
			revokedSessions = append(revokedSessions, sess)
		}
	}
	c.mu.Unlock()

	for _, sess := range revokedSessions {
		_ = sess.CloseWithReason("peer_revoked")
	}
	return nil
}

// UpdateNetwork swaps the virtual network stack (used in T11 network-change simulation)
// and triggers bounded ICE restart on active sessions.
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
// single-use challenge-response registration.
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

	// Read challenge from Hub.
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

	regPayload, err := json.Marshal(protocol.RegisterMessage{
		V:          protocol.Version,
		Type:       protocol.TypeRegister,
		PeerID:     c.cfg.KeyPair.PeerID,
		PublicKey:  identity.EncodePublicKey(c.cfg.KeyPair.PublicKey),
		HubOrigin:  c.hubOrigin,
		Challenge:  chal.Challenge,
		Membership: c.cfg.Membership,
		Proof:      proof,
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
	go c.wsHeartbeatLoop(conn, hbInterval, wsDone)
	return nil
}

// Close shuts down all peer sessions and closes the WSS signaling connection.
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

	c.wg.Wait()
	return nil
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

func (c *Client) wsHeartbeatLoop(conn *websocket.Conn, interval time.Duration, wsDone <-chan struct{}) {
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

// handleWSLoss implements Section 4.3 & Section 5.2:
//   - Abandon any negotiation that has not yet reached Connected (so retries use a fresh session_id).
//   - Preserve already-Connected direct P2P sessions during hub outages (T10).
func (c *Client) handleWSLoss(lostConn *websocket.Conn) {
	c.wsMu.Lock()
	if c.wsConn == lostConn {
		c.wsConn = nil
		c.wsOnline.Store(false)
	}
	c.wsMu.Unlock()

	c.mu.Lock()
	for target, waiters := range c.pendingLookups {
		for _, ch := range waiters {
			ch <- lookupWaiter{err: ErrHubDisconnected}
		}
		delete(c.pendingLookups, target)
	}
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
	case protocol.TypeLookupResult:
		var lr protocol.LookupResultMessage
		if err := jcs.UnmarshalStrict(raw, &lr); err != nil {
			c.lastSignalRejected.Add(1)
			return
		}
		c.mu.Lock()
		waiters := c.pendingLookups[lr.Target]
		delete(c.pendingLookups, lr.Target)
		c.mu.Unlock()
		for _, ch := range waiters {
			ch <- lookupWaiter{res: lr}
		}

	case protocol.TypeError:
		var em protocol.ErrorMessage
		if err := jcs.UnmarshalStrict(raw, &em); err != nil {
			return
		}
		c.mu.Lock()
		if em.SessionID != "" {
			if sess, ok := c.sessionsByID[em.SessionID]; ok {
				c.mu.Unlock()
				sess.failClosed(em.Code, fmt.Errorf("hub error: %s", em.Code))
				return
			}
		}
		// Wake earliest lookup waiter if error was for a lookup.
		for target, waiters := range c.pendingLookups {
			for _, ch := range waiters {
				ch <- lookupWaiter{err: fmt.Errorf("%w: %s", ErrPeerOfflineOrDenied, em.Code)}
			}
			delete(c.pendingLookups, target)
			break
		}
		c.mu.Unlock()

	case protocol.TypeOffer, protocol.TypeAnswer, protocol.TypeCandidate, protocol.TypeEndOfCandidates, protocol.TypeClose:
		cp := append([]byte(nil), raw...)
		select {
		case c.signalCh <- cp:
		case <-c.stopCh:
		}
	}
}

func (c *Client) signalWorkerLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.stopCh:
			return
		case raw := <-c.signalCh:
			if err := c.handlePeerEnvelope(raw); err != nil {
				c.lastSignalRejected.Add(1)
				c.log.Warn("rejected peer signaling envelope", "err", err)
			}
		}
	}
}

// Lookup queries the hub for targetPeerID and independently verifies its identity and ACL locally.
func (c *Client) Lookup(ctx context.Context, targetPeerID string) (*identity.VerifiedPeer, bool, error) {
	if err := identity.ValidatePeerID(targetPeerID); err != nil {
		return nil, false, err
	}
	waitCh := make(chan lookupWaiter, 1)
	c.mu.Lock()
	c.pendingLookups[targetPeerID] = append(c.pendingLookups[targetPeerID], waitCh)
	c.mu.Unlock()

	reqBytes, err := json.Marshal(protocol.LookupMessage{
		V:      protocol.Version,
		Type:   protocol.TypeLookup,
		Target: targetPeerID,
	})
	if err != nil {
		return nil, false, err
	}
	if err := c.sendWS(ctx, reqBytes); err != nil {
		c.removeLookupWaiter(targetPeerID, waitCh)
		return nil, false, err
	}

	select {
	case <-ctx.Done():
		c.removeLookupWaiter(targetPeerID, waitCh)
		return nil, false, ctx.Err()
	case out := <-waitCh:
		if out.err != nil {
			return nil, false, out.err
		}
		var pub ed25519.PublicKey
		if out.res.PublicKey != "" {
			pub, err = identity.DecodePublicKey(out.res.PublicKey)
			if err != nil {
				return nil, false, err
			}
		}
		// Section 3 & SEC-02: Independently verify peer trust and ACL locally!
		vp, err := c.trust.VerifyPeer(targetPeerID, pub, out.res.Membership)
		if err != nil {
			return nil, false, err
		}
		if err := c.trust.AuthorizePair(c.PeerID(), targetPeerID, c.cfg.Membership, vp.Membership); err != nil {
			return nil, false, err
		}
		c.trust.CacheVerifiedPeer(vp)
		return vp, out.res.Online, nil
	}
}

func (c *Client) removeLookupWaiter(target string, targetCh chan lookupWaiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := c.pendingLookups[target]
	kept := list[:0]
	for _, ch := range list {
		if ch != targetCh {
			kept = append(kept, ch)
		}
	}
	if len(kept) == 0 {
		delete(c.pendingLookups, target)
	} else {
		c.pendingLookups[target] = kept
	}
}

func (c *Client) resolveVerifiedRemotePeer(ctx context.Context, remotePeerID string) (*identity.VerifiedPeer, error) {
	if vp, err := c.trust.VerifyPeer(remotePeerID, nil, nil); err == nil {
		if aclErr := c.trust.AuthorizePair(c.PeerID(), remotePeerID, c.cfg.Membership, vp.Membership); aclErr != nil {
			return nil, aclErr
		}
		return vp, nil
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	vp, _, err := c.Lookup(lctx, remotePeerID)
	if err != nil {
		return nil, err
	}
	return vp, nil
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

func (c *Client) handlePeerEnvelope(raw []byte) error {
	env, err := protocol.ParseUnsignedEnvelope(raw, protocol.MaxSignalingMessageSize)
	if err != nil {
		return err
	}
	if env.To != c.PeerID() {
		return protocol.ErrInvalidEnvelope
	}

	vp, err := c.resolveVerifiedRemotePeer(context.Background(), env.From)
	if err != nil {
		return err
	}

	if err := protocol.VerifyEnvelopeSignature(env, vp.PublicKey, time.Now(), c.cfg.SignalingTTL, c.cfg.MaxClockSkew); err != nil {
		return err
	}

	c.mu.Lock()
	if _, wasClosed := c.closedSessionIDs[env.SessionID]; wasClosed {
		c.mu.Unlock()
		return ErrReplayedSignaling
	}

	sessByID := c.sessionsByID[env.SessionID]
	sessByPeer := c.sessionsByPeer[env.From]

	// Handle incoming offer (new session, glare resolution, or ICE restart generation).
	if env.Type == protocol.TypeOffer {
		if sessByID != nil {
			c.mu.Unlock()
			return sessByID.receiveVerifiedEnvelope(env, raw)
		}

		// Glare check (Section 5): concurrent offers for the same peer pair.
		if sessByPeer != nil {
			st := sessByPeer.State()
			if st == StateDiscovering || st == StateNegotiating {
				// Offer from lexicographically smaller peer_id wins!
				if c.PeerID() < env.From {
					// Local outgoing offer wins; ignore remote losing offer.
					c.mu.Unlock()
					return nil
				}
				// Remote offer wins! Supersede our outgoing negotiation cleanly and adopt env.SessionID.
				delete(c.sessionsByID, sessByPeer.SessionID())
				c.closedSessionIDs[sessByPeer.SessionID()] = time.Now()
				c.sessionsByID[env.SessionID] = sessByPeer
				c.mu.Unlock()
				return sessByPeer.adoptWinningRemoteOffer(env, raw, vp)
			}
			if st == StateConnected || st == StateAuthenticating || st == StateReconnecting {
				// Replace old session if remote peer re-established fresh session.
				delete(c.sessionsByID, sessByPeer.SessionID())
				c.closedSessionIDs[sessByPeer.SessionID()] = time.Now()
				c.mu.Unlock()
				sessByPeer.failClosed("superseded_by_new_offer", ErrSessionClosed)
				c.mu.Lock()
			}
		}

		if env.Seq != 0 {
			c.mu.Unlock()
			return ErrReplayedSignaling
		}

		sess := newSession(c, vp, env.SessionID, false)
		c.sessionsByPeer[env.From] = sess
		c.sessionsByID[env.SessionID] = sess
		c.mu.Unlock()

		if err := sess.receiveVerifiedEnvelope(env, raw); err != nil {
			c.removeSession(sess, true)
			return err
		}
		return nil
	}

	if sessByID == nil || sessByID.remotePeer.PeerID != env.From {
		c.mu.Unlock()
		return ErrReplayedSignaling
	}
	c.mu.Unlock()

	return sessByID.receiveVerifiedEnvelope(env, raw)
}

// Connect initiates a direct-only authenticated WebRTC session to targetPeerID
// and blocks until StateConnected is reached or OfferToConnectedTimeout/ctx expires.
func (c *Client) Connect(ctx context.Context, targetPeerID string) (*Session, error) {
	if !c.wsOnline.Load() {
		return nil, ErrHubDisconnected
	}

	sessionID, err := protocol.NewSessionID()
	if err != nil {
		return nil, err
	}

	sess := newSession(c, &identity.VerifiedPeer{PeerID: targetPeerID}, sessionID, true)
	sess.setState(StateDiscovering, "")

	deadlineCtx, cancel := context.WithTimeout(ctx, c.cfg.OfferToConnectedTimeout)
	defer cancel()

	// Step 1: Discovering -> Authorized Lookup + local independent trust verification.
	vp, online, err := c.Lookup(deadlineCtx, targetPeerID)
	if err != nil || !online {
		sess.failClosed("offline_or_denied", ErrPeerOfflineOrDenied)
		if err != nil {
			return nil, err
		}
		return nil, ErrPeerOfflineOrDenied
	}
	sess.remotePeer = vp

	c.mu.Lock()
	if existing, ok := c.sessionsByPeer[targetPeerID]; ok {
		st := existing.State()
		if st == StateNegotiating || st == StateAuthenticating || st == StateConnected {
			c.mu.Unlock()
			return existing.waitConnected(deadlineCtx)
		}
	}
	c.sessionsByPeer[targetPeerID] = sess
	c.sessionsByID[sessionID] = sess
	c.mu.Unlock()

	// Step 2: Negotiating -> Create data-only offer and exchange signed SDP & Trickle ICE.
	if err := sess.startAsOfferer(deadlineCtx, 0); err != nil {
		// Check if glare switched this session to responder in the meantime.
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
	if sess.remotePeer != nil {
		if cur := c.sessionsByPeer[sess.remotePeer.PeerID]; cur == sess {
			delete(c.sessionsByPeer, sess.remotePeer.PeerID)
		}
	}
	if markClosed && sess.sessionID != "" {
		c.closedSessionIDs[sess.sessionID] = time.Now()
	}
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
	// Section 6 & 8.1: Enforce DTLS 1.3 exclusively, replay protection enabled, fingerprint verification enabled.
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
	if vnet != nil {
		se.SetNet(vnet)
	}

	// Filter remote IPs if any non-local Hub host IPs are prohibited.
	if len(c.prohibitedIPs) > 0 {
		blocked := append([]net.IP(nil), c.prohibitedIPs...)
		se.SetRemoteIPFilter(func(ip net.IP) bool {
			for _, bip := range blocked {
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

// Session represents a direct-only authenticated WebRTC connection with one remote peer.
type Session struct {
	client     *Client
	remotePeer *identity.VerifiedPeer

	sendSignalMu       sync.Mutex
	mu                 sync.Mutex
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

func newSession(client *Client, remote *identity.VerifiedPeer, sessionID string, initiator bool) *Session {
	s := &Session{
		client:             client,
		remotePeer:         remote,
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

// SessionID returns the active 128-bit base64url negotiation session ID.
func (s *Session) SessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

// RemotePeerID returns the authenticated remote peer_id.
func (s *Session) RemotePeerID() string {
	if s.remotePeer == nil {
		return ""
	}
	return s.remotePeer.PeerID
}

// State returns the current ConnectionState.
func (s *Session) State() ConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// IsPathVerified reports whether DTLS 1.3, certificate fingerprint, direct ICE pair,
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

// Send transmits an ordered, reliable binary message over "data/v1" (<= 16 KiB)
// with bounded queue backpressure.
func (s *Session) Send(ctx context.Context, payload []byte) error {
	st := s.State()
	if st == StateFailed || st == StateDisconnected {
		return ErrSessionClosed
	}
	return s.dataCh.enqueue(ctx, payload)
}

// SendPacket transmits an optional unordered, non-retransmitted datagram over "packet/v1".
func (s *Session) SendPacket(ctx context.Context, payload []byte) error {
	st := s.State()
	if st == StateFailed || st == StateDisconnected {
		return ErrSessionClosed
	}
	return s.packetCh.enqueue(ctx, payload)
}

// Messages returns the receive channel for verified "data/v1" binary payloads.
func (s *Session) Messages() <-chan []byte {
	return s.recvDataCh
}

// Packets returns the receive channel for verified "packet/v1" datagram payloads.
func (s *Session) Packets() <-chan []byte {
	return s.recvPacketCh
}

// Diagnostics returns an observability snapshot of transport security and ICE metrics (Section 9 & 10).
func (s *Session) Diagnostics() SessionDiagnostics {
	s.mu.Lock()
	diag := SessionDiagnostics{
		SessionID:        s.sessionID,
		Generation:       s.generation,
		State:            s.state,
		RemoteCertSHA256: s.verifiedRemoteFP,
		FailureCode:      s.failureCode,
	}
	if s.remotePeer != nil {
		diag.RemotePeerID = s.remotePeer.PeerID
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

	if s.remotePeer != nil && sid != "" && s.client.wsOnline.Load() {
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
}

func (s *Session) resetGenerationLocked(gen uint32) *webrtc.PeerConnection {
	oldPC := s.pc
	s.pc = nil
	s.generation = gen
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
	var iceServers []webrtc.ICEServer
	if s.client.cfg.STUNServerURI != "" {
		iceServers = []webrtc.ICEServer{{URLs: []string{s.client.cfg.STUNServerURI}}}
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: iceServers,
	})
	if err != nil {
		return nil, err
	}
	s.pc = pc

	// Enforce offer-to-connected deadline for every negotiation/restart generation.
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

	// Trickle ICE candidate emission.
	pc.OnICECandidate(func(cand *webrtc.ICECandidate) {
		s.onLocalICECandidate(gen, pc, cand)
	})

	// Monitor ICE transport pair nomination and runtime path changes (Section 5.1).
	iceT := pc.SCTP().Transport().ICETransport()
	iceT.OnSelectedCandidatePairChange(func(pair *webrtc.ICECandidatePair) {
		s.onSelectedPairChange(gen, pc, pair)
	})
	iceT.OnConnectionStateChange(func(st webrtc.ICETransportState) {
		s.onICEStateChange(gen, pc, st)
	})

	// Monitor DTLS 1.3 handshake state and certificate fingerprint (Section 6).
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
	// Wrap OnOpen while preserving managedChannel's state update.
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

	// Section 7: Answerer accepts ONLY negotiated, recognized labels and exact reliability settings.
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
		// Reject unrecognized DataChannel labels immediately.
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

func (s *Session) adoptWinningRemoteOffer(env *protocol.SignalEnvelope, raw []byte, vp *identity.VerifiedPeer) error {
	s.mu.Lock()
	oldPC := s.resetGenerationLocked(env.Generation)
	s.sessionID = env.SessionID
	s.remotePeer = vp
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

	if env.Generation < s.generation {
		s.mu.Unlock()
		return ErrStaleGeneration
	}

	if env.Generation > s.generation {
		// New generation must begin with an offer at seq 0 (ICE restart).
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
		// Section 4.3 & T07: Reject replayed offers/answers/closes or modified retransmissions;
		// deduplicate identical candidate/end_of_candidates retransmissions without reinstalling.
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

	// Process contiguous envelopes starting from s.nextRemoteSeq.
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
	switch env.Type {
	case protocol.TypeOffer:
		var body protocol.SDPBody
		if err := jcs.UnmarshalStrict(env.Body, &body); err != nil {
			return err
		}
		info, err := ValidateAndInspectRemoteSDP(body.SDP, s.client.prohibitedEndpoints, s.client.prohibitedIPs)
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
		info, err := ValidateAndInspectRemoteSDP(body.SDP, s.client.prohibitedEndpoints, s.client.prohibitedIPs)
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
		// Section 5.1 & T08: Reject prohibited candidates BEFORE buffering or installing into WebRTC!
		if err := ValidateTrickleCandidate(body, s.client.prohibitedEndpoints, s.client.prohibitedIPs); err != nil {
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

	// Never emit relay or non-UDP candidates locally either.
	if !isAllowedWebRTCCandidateType(cand.Typ) || cand.Protocol != webrtc.ICEProtocolUDP {
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
	for _, line := range strings.Split(rawSDP, "\n") {
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
	if s.generation != gen || s.remotePeer == nil {
		s.mu.Unlock()
		return ErrStaleGeneration
	}
	seq := s.localSeq
	s.localSeq++
	sid := s.sessionID
	to := s.remotePeer.PeerID
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
	if err := ValidateSelectedPair(pair, s.client.prohibitedEndpoints, s.client.prohibitedIPs); err != nil {
		// Section 5.1: Immediately suspend traffic and close on prohibited/unverifiable path!
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
		// Suspend application traffic while path is unverified and attempt bounded ICE restart.
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
		// Section 6 & SEC-01: Enforce DTLS 1.3 (0xFEFC) exclusively; downgrade MUST fail!
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

		// Section 3 & 6: Verify remote DTLS certificate SHA-256 matches Ed25519-signed SDP!
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
	// Double-check live selected candidate pair right before enabling user payloads.
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || ValidateSelectedPair(pair, s.client.prohibitedEndpoints, s.client.prohibitedIPs) != nil {
		return
	}

	s.mu.Lock()
	if s.pc != pc || s.generation != gen || !s.pairReady || !s.dtlsReady || !s.dataReady {
		s.mu.Unlock()
		return
	}
	if s.state == StateFailed || s.state == StateDisconnected {
		s.mu.Unlock()
		return
	}
	s.restarting = false
	firstConnect := !s.notifiedApp
	isInitiator := s.isInitiator
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
	if firstConnect && !isInitiator && s.client.cfg.OnSession != nil {
		go s.client.cfg.OnSession(s)
	}
}

// RestartICE manually triggers a bounded signed ICE restart on an established session.
func (s *Session) RestartICE(ctx context.Context) error {
	s.triggerNetworkChange()
	budget := s.client.cfg.OfferToConnectedTimeout + s.client.cfg.ICERestartBackoff*time.Duration(1<<max(0, s.client.cfg.MaxICERestarts))
	deadline, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		st := s.State()
		if st == StateConnected && s.IsPathVerified() {
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
		// Initial negotiation failed before ever reaching Connected -> fail closed immediately.
		if reason == "ice_failed" || reason == "peer_connection_failed" {
			s.mu.Unlock()
			s.failClosed(reason, errors.New("peer: direct ICE negotiation failed"))
			return
		}
		s.mu.Unlock()
		return
	}

	// Section 5.2: Suspend new payload transmission immediately when path is not verified.
	s.pathVerified.Store(false)
	s.dataCh.setPathAllowed(false)
	s.packetCh.setPathAllowed(false)

	if s.restarting {
		s.mu.Unlock()
		return
	}
	if !s.client.wsOnline.Load() {
		// Hub unavailable: cannot coordinate signed ICE restart -> fail closed once path dies.
		if reason == "ice_failed" || reason == "peer_connection_failed" || reason == "network_change" {
			s.mu.Unlock()
			s.failClosed("hub_unavailable_for_restart", ErrHubDisconnected)
			return
		}
		s.mu.Unlock()
		return
	}

	// Deterministic restart initiator: lexicographically smaller peer_id drives offerer role
	// unless network_change was explicitly triggered on this endpoint.
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
