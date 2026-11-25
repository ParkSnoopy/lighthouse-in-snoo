package stunserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v4"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/logging"
	"github.com/pion/stun/v5"
	"golang.org/x/time/rate"

	"lighthouse-in-snoo/internal/ratelimit"
)

const (
	// MinSTUNHeaderBytes is the fixed 20-byte RFC 8489 STUN header length.
	MinSTUNHeaderBytes = 20
	// stunMagicCookie is the fixed RFC 8489 Section 6 STUN magic cookie.
	stunMagicCookie uint32 = 0x2112A442
	// DefaultMaxDatagramBytes bounds incoming plaintext STUN messages.
	DefaultMaxDatagramBytes = 576
	// DefaultMaxDTLSDatagramBytes bounds raw UDP datagrams carrying DTLS 1.3 records.
	DefaultMaxDTLSDatagramBytes = 4096
	// DefaultSTUNSAddr is the default RFC 7350 DTLS/UDP (or TLS/TCP in --tcp-only) STUNS port.
	DefaultSTUNSAddr = ":5349"
	// DefaultInsecureSTUNAddr is the default plaintext STUN port (opt-in only).
	DefaultInsecureSTUNAddr = ":3478"
)

// ErrInsecureSTUNProhibited is returned when plaintext STUN is configured without AllowInsecure.
var ErrInsecureSTUNProhibited = errors.New("stunserver: plaintext STUN requires AllowInsecure=true; use encrypted STUNS")

// Config configures the RFC 8489 / RFC 7350 STUN Binding server.
// By default it serves STUNS over DTLS 1.3 / UDP (:5349/udp).
// For TCP-only deployments, configure TLSListenAddr/TLSListener to serve STUNS over TLS 1.3 / TCP with zero UDP sockets.
// Plaintext UDP or TCP STUN requires AllowInsecure=true.
type Config struct {
	DTLSListenAddr string         // UDP listen address for DTLS 1.3 STUNS (default :5349 when not TCP-only).
	DTLSPacketConn net.PacketConn // Optional pre-bound UDP PacketConn wrapped with DTLS 1.3.
	TLSListenAddr  string         // Optional TCP listen address for TLS 1.3 STUNS (TCP-only mode).
	TLSListener    net.Listener   // Optional pre-bound TCP listener wrapped with TLS 1.3.
	TLSConfig      *tls.Config    // Required for DTLS 1.3 or TLS 1.3 STUNS (provides server certificate chain).

	AllowInsecure bool           // Explicit opt-in required to serve plaintext UDP/TCP STUN.
	ListenAddr    string         // Plaintext UDP listen address (requires AllowInsecure).
	PacketConn    net.PacketConn // Optional pre-bound plaintext UDP PacketConn (requires AllowInsecure).
	TCPListenAddr string         // Plaintext TCP listen address (requires AllowInsecure).
	TCPListener   net.Listener   // Optional pre-bound plaintext TCP listener (requires AllowInsecure).

	MaxDatagramBytes int
	PerIPRPS         float64
	PerIPBurst       int
	MaxTrackedIPs    int
	MaxConnsPerIP    int
	MaxTotalConns    int
	GlobalRPS        float64
	GlobalBurst      int
	DTLSReadTimeout  time.Duration
	LoggerFactory    logging.LoggerFactory
	Logger           *slog.Logger
}

// Stats exposes aggregate non-sensitive STUN/STUNS operational counters.
type Stats struct {
	BindingRequests    uint64
	BindingResponses   uint64
	UnsupportedMethods uint64
	MalformedPackets   uint64
	OversizedPackets   uint64
	RateLimited        uint64
}

// Server implements an RFC 8489 / RFC 7350 STUN Binding responder returning XOR-MAPPED-ADDRESS
// over DTLS 1.3 / UDP (default), TLS 1.3 / TCP (TCP-only), and optionally plaintext UDP/TCP when AllowInsecure is set.
type Server struct {
	dtlsLn       net.Listener
	dtlsRawConn  net.PacketConn
	ownsDTLSConn bool
	tlsLn        net.Listener
	udpConn      net.PacketConn
	ownsUDP      bool
	tcpLn        net.Listener
	maxBytes     int
	readTimeout  time.Duration
	ipLimiter    *ratelimit.KeyedLimiter
	connConc     *ratelimit.ConcurrencyLimiter
	globalLim    *rate.Limiter
	log          *slog.Logger
	closed       atomic.Bool
	activeMu     sync.Mutex
	activeConns  map[net.Conn]struct{}
	wg           sync.WaitGroup

	bindingReqs        atomic.Uint64
	bindingResps       atomic.Uint64
	unsupportedMethods atomic.Uint64
	malformedPackets   atomic.Uint64
	oversizedPackets   atomic.Uint64
	rateLimited        atomic.Uint64
}

// New creates and starts a STUNS (DTLS 1.3/UDP or TLS 1.3/TCP) and/or opt-in insecure STUN Binding server.
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("stunserver: config is required")
	}
	wantsPlainUDP := cfg.ListenAddr != "" || cfg.PacketConn != nil
	wantsPlainTCP := cfg.TCPListenAddr != "" || cfg.TCPListener != nil
	if (wantsPlainUDP || wantsPlainTCP) && !cfg.AllowInsecure {
		return nil, ErrInsecureSTUNProhibited
	}

	wantsTLS := cfg.TLSListenAddr != "" || cfg.TLSListener != nil
	wantsDTLS := cfg.DTLSListenAddr != "" || cfg.DTLSPacketConn != nil ||
		(cfg.TLSConfig != nil && !wantsTLS && !wantsPlainUDP && !wantsPlainTCP)
	if !wantsDTLS && !wantsTLS && !wantsPlainUDP && !wantsPlainTCP {
		return nil, errors.New("stunserver: TLSConfig is required for encrypted STUNS (or opt in with AllowInsecure)")
	}
	if (wantsDTLS || wantsTLS) && (cfg.TLSConfig == nil || len(cfg.TLSConfig.Certificates) == 0) {
		return nil, errors.New("stunserver: TLSConfig with certificate is required for DTLS/TLS STUNS")
	}

	maxBytes := cfg.MaxDatagramBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDatagramBytes
	}
	perIPRPS := cfg.PerIPRPS
	if perIPRPS <= 0 {
		perIPRPS = 50
	}
	perIPBurst := cfg.PerIPBurst
	if perIPBurst <= 0 {
		perIPBurst = 100
	}
	maxIPs := cfg.MaxTrackedIPs
	if maxIPs <= 0 {
		maxIPs = 8192
	}
	maxConnsPerIP := cfg.MaxConnsPerIP
	if maxConnsPerIP <= 0 {
		maxConnsPerIP = 64
	}
	maxTotalConns := cfg.MaxTotalConns
	if maxTotalConns <= 0 {
		maxTotalConns = 4096
	}
	globalRPS := cfg.GlobalRPS
	if globalRPS <= 0 {
		globalRPS = 5000
	}
	globalBurst := cfg.GlobalBurst
	if globalBurst <= 0 {
		globalBurst = 10000
	}
	readTimeout := cfg.DTLSReadTimeout
	if readTimeout <= 0 {
		readTimeout = 10 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	lf := cfg.LoggerFactory
	if lf == nil {
		dlf := logging.NewDefaultLoggerFactory()
		dlf.DefaultLogLevel = logging.LogLevelError
		lf = dlf
	}

	s := &Server{
		maxBytes:    maxBytes,
		readTimeout: readTimeout,
		ipLimiter:   ratelimit.NewKeyedLimiter(perIPRPS, perIPBurst, maxIPs, 5*time.Minute),
		connConc:    ratelimit.NewConcurrencyLimiter(maxConnsPerIP, maxTotalConns),
		globalLim:   rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
		log:         logger,
		activeConns: make(map[net.Conn]struct{}),
	}

	cleanupOnErr := func() {
		if s.dtlsLn != nil {
			_ = s.dtlsLn.Close()
		}
		if s.ownsDTLSConn && s.dtlsRawConn != nil {
			_ = s.dtlsRawConn.Close()
		}
		if s.tlsLn != nil {
			_ = s.tlsLn.Close()
		}
		if s.ownsUDP && s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		if s.tcpLn != nil {
			_ = s.tcpLn.Close()
		}
	}

	if wantsDTLS {
		rawConn := cfg.DTLSPacketConn
		ownsDTLS := false
		if rawConn == nil {
			addr := cfg.DTLSListenAddr
			if addr == "" {
				addr = DefaultSTUNSAddr
			}
			var err error
			rawConn, err = net.ListenPacket("udp", addr)
			if err != nil {
				return nil, fmt.Errorf("listen stuns dtls/udp %s: %w", addr, err)
			}
			ownsDTLS = true
		}

		filtered := &guardedDTLSPacketConn{
			PacketConn: rawConn,
			srv:        s,
			maxRawSize: DefaultMaxDTLSDatagramBytes,
		}
		dtlsLn, err := dtls.Listen(filtered,
			dtls.WithCertificates(cfg.TLSConfig.Certificates...),
			dtls.WithMinVersion(dtlsProtocol.Version1_3),
			dtls.WithMaxVersion(dtlsProtocol.Version1_3),
			dtls.WithReplayProtectionWindow(64),
			dtls.WithFlightInterval(100*time.Millisecond),
			dtls.WithLoggerFactory(lf),
		)
		if err != nil {
			if ownsDTLS {
				_ = rawConn.Close()
			}
			return nil, fmt.Errorf("start stuns dtls listener: %w", err)
		}
		s.dtlsLn = dtlsLn
		s.dtlsRawConn = rawConn
		s.ownsDTLSConn = ownsDTLS
	}

	if wantsTLS {
		tcfg := cfg.TLSConfig.Clone()
		tcfg.MinVersion = tls.VersionTLS13
		tcfg.MaxVersion = tls.VersionTLS13

		rawLn := cfg.TLSListener
		if rawLn == nil {
			addr := cfg.TLSListenAddr
			if addr == "" {
				addr = DefaultSTUNSAddr
			}
			var err error
			rawLn, err = net.Listen("tcp", addr)
			if err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("listen stuns tls/tcp %s: %w", addr, err)
			}
		}
		s.tlsLn = tls.NewListener(rawLn, tcfg)
	}

	if wantsPlainUDP {
		udpConn := cfg.PacketConn
		ownsUDP := false
		if udpConn == nil {
			addr := cfg.ListenAddr
			if addr == "" {
				addr = DefaultInsecureSTUNAddr
			}
			var err error
			udpConn, err = net.ListenPacket("udp", addr)
			if err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("listen insecure stun udp %s: %w", addr, err)
			}
			ownsUDP = true
		}
		s.udpConn = udpConn
		s.ownsUDP = ownsUDP
	}

	if wantsPlainTCP {
		tcpLn := cfg.TCPListener
		if tcpLn == nil {
			addr := cfg.TCPListenAddr
			if addr == "" {
				addr = DefaultInsecureSTUNAddr
			}
			var err error
			tcpLn, err = net.Listen("tcp", addr)
			if err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("listen insecure stun tcp %s: %w", addr, err)
			}
		}
		s.tcpLn = tcpLn
	}

	if s.dtlsLn != nil {
		s.wg.Add(1)
		go s.serveDTLSLoop()
	}
	if s.tlsLn != nil {
		s.wg.Add(1)
		go s.serveStreamLoop(s.tlsLn)
	}
	if s.udpConn != nil {
		s.wg.Add(1)
		go s.serveUDPLoop()
	}
	if s.tcpLn != nil {
		s.wg.Add(1)
		go s.serveStreamLoop(s.tcpLn)
	}
	return s, nil
}

// DTLSAddr returns the bound DTLS 1.3 / UDP STUNS address, or nil if disabled.
func (s *Server) DTLSAddr() net.Addr {
	if s.dtlsLn == nil {
		return nil
	}
	return s.dtlsLn.Addr()
}

// TLSAddr returns the bound TLS 1.3 / TCP STUNS address, or nil if disabled.
func (s *Server) TLSAddr() net.Addr {
	if s.tlsLn == nil {
		return nil
	}
	return s.tlsLn.Addr()
}

// UDPAddr returns the bound plaintext UDP STUN address, or nil if disabled.
func (s *Server) UDPAddr() net.Addr {
	if s.udpConn == nil {
		return nil
	}
	return s.udpConn.LocalAddr()
}

// TCPAddr returns the bound plaintext TCP STUN address, or nil if disabled.
func (s *Server) TCPAddr() net.Addr {
	if s.tcpLn == nil {
		return nil
	}
	return s.tcpLn.Addr()
}

// LocalAddr returns the primary active STUNS/STUN address.
func (s *Server) LocalAddr() net.Addr {
	if s.dtlsLn != nil {
		return s.dtlsLn.Addr()
	}
	if s.tlsLn != nil {
		return s.tlsLn.Addr()
	}
	if s.udpConn != nil {
		return s.udpConn.LocalAddr()
	}
	if s.tcpLn != nil {
		return s.tcpLn.Addr()
	}
	return nil
}

// Stats returns a snapshot of aggregate STUN/STUNS counters.
func (s *Server) Stats() Stats {
	return Stats{
		BindingRequests:    s.bindingReqs.Load(),
		BindingResponses:   s.bindingResps.Load(),
		UnsupportedMethods: s.unsupportedMethods.Load(),
		MalformedPackets:   s.malformedPackets.Load(),
		OversizedPackets:   s.oversizedPackets.Load(),
		RateLimited:        s.rateLimited.Load(),
	}
}

// Close shuts down the STUNS/STUN server cleanly.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	var dtlsErr, rawErr, tlsErr, udpErr, tcpErr error
	if s.dtlsLn != nil {
		dtlsErr = s.dtlsLn.Close()
	}
	if s.tlsLn != nil {
		if err := s.tlsLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			tlsErr = err
		}
	}
	if s.tcpLn != nil {
		if err := s.tcpLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			tcpErr = err
		}
	}
	s.activeMu.Lock()
	conns := make([]net.Conn, 0, len(s.activeConns))
	for c := range s.activeConns {
		conns = append(conns, c)
	}
	s.activeMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	if s.dtlsRawConn != nil {
		if s.ownsDTLSConn {
			if err := s.dtlsRawConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				rawErr = err
			}
		} else {
			_ = s.dtlsRawConn.SetReadDeadline(time.Now())
		}
	}
	if s.udpConn != nil {
		if s.ownsUDP {
			udpErr = s.udpConn.Close()
		} else {
			_ = s.udpConn.SetReadDeadline(time.Now())
		}
	}
	s.wg.Wait()
	return errors.Join(dtlsErr, rawErr, tlsErr, udpErr, tcpErr)
}

type guardedDTLSPacketConn struct {
	net.PacketConn
	srv        *Server
	maxRawSize int
}

func (g *guardedDTLSPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, raddr, err := g.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		ip, _, ok := extractIPPort(raddr)
		if !ok {
			g.srv.malformedPackets.Add(1)
			continue
		}
		if !g.srv.globalLim.Allow() || !g.srv.ipLimiter.Allow(ip.String()) {
			g.srv.rateLimited.Add(1)
			continue
		}
		if n > g.maxRawSize {
			g.srv.oversizedPackets.Add(1)
			continue
		}
		if n == 0 || !isDTLSRecordByte(p[0]) {
			// Plaintext STUN/TURN or garbage datagrams sent to the DTLS STUNS port are rejected.
			if n >= MinSTUNHeaderBytes && stun.IsMessage(p[:n]) {
				var msg stun.Message
				if stun.Decode(p[:n], &msg) == nil && msg.Type.Method != stun.MethodBinding {
					g.srv.unsupportedMethods.Add(1)
				} else {
					g.srv.malformedPackets.Add(1)
				}
			} else {
				g.srv.malformedPackets.Add(1)
			}
			continue
		}
		return n, raddr, nil
	}
}

func isDTLSRecordByte(b byte) bool {
	// DTLS 1.2/1.3 plaintext content types (20..25) or DTLS 1.3 unified ciphertext header (001xxxxx).
	if b >= 20 && b <= 25 {
		return true
	}
	return dtlsProtocol.IsDTLS13Ciphertext(dtlsProtocol.ContentType(b))
}

func (s *Server) serveDTLSLoop() {
	defer s.wg.Done()

	for !s.closed.Load() {
		conn, err := s.dtlsLn.Accept()
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		ip, port, ok := extractIPPort(conn.RemoteAddr())
		if !ok {
			s.malformedPackets.Add(1)
			_ = conn.Close()
			continue
		}

		ipKey := ip.String()
		if !s.connConc.Acquire(ipKey) {
			s.rateLimited.Add(1)
			_ = conn.Close()
			continue
		}

		s.activeMu.Lock()
		if s.closed.Load() {
			s.activeMu.Unlock()
			s.connConc.Release(ipKey)
			_ = conn.Close()
			return
		}
		s.activeConns[conn] = struct{}{}
		s.activeMu.Unlock()

		s.wg.Add(1)
		go func(c net.Conn, remoteIP net.IP, remotePort int, key string) {
			defer s.wg.Done()
			defer func() {
				s.activeMu.Lock()
				delete(s.activeConns, c)
				s.activeMu.Unlock()
			}()
			defer s.connConc.Release(key)
			defer c.Close()
			s.handleDTLSConn(c, remoteIP, remotePort, key)
		}(conn, ip, port, ipKey)
	}
}

func (s *Server) handleDTLSConn(conn net.Conn, remoteIP net.IP, remotePort int, ipKey string) {
	if dc, ok := conn.(*dtls.Conn); ok {
		hsCtx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
		err := dc.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			return
		}
	}

	buf := make([]byte, s.maxBytes+1)
	var req stun.Message
	var resp stun.Message

	for !s.closed.Load() {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if !s.globalLim.Allow() || !s.ipLimiter.Allow(ipKey) {
			s.rateLimited.Add(1)
			return
		}
		if n > s.maxBytes {
			s.oversizedPackets.Add(1)
			continue
		}
		if n < MinSTUNHeaderBytes || !stun.IsMessage(buf[:n]) {
			s.malformedPackets.Add(1)
			continue
		}

		out, shouldReply := s.processMessage(&req, &resp, buf[:n], remoteIP, remotePort)
		if !shouldReply {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
		if resp.Type == stun.BindingSuccess {
			s.bindingResps.Add(1)
		}
	}
}

func (s *Server) serveStreamLoop(ln net.Listener) {
	defer s.wg.Done()

	for !s.closed.Load() {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		ip, port, ok := extractIPPort(conn.RemoteAddr())
		if !ok {
			s.malformedPackets.Add(1)
			_ = conn.Close()
			continue
		}

		ipKey := ip.String()
		if !s.connConc.Acquire(ipKey) {
			s.rateLimited.Add(1)
			_ = conn.Close()
			continue
		}

		s.activeMu.Lock()
		if s.closed.Load() {
			s.activeMu.Unlock()
			s.connConc.Release(ipKey)
			_ = conn.Close()
			return
		}
		s.activeConns[conn] = struct{}{}
		s.activeMu.Unlock()

		s.wg.Add(1)
		go func(c net.Conn, remoteIP net.IP, remotePort int, key string) {
			defer s.wg.Done()
			defer func() {
				s.activeMu.Lock()
				delete(s.activeConns, c)
				s.activeMu.Unlock()
			}()
			defer s.connConc.Release(key)
			defer c.Close()
			s.handleStreamConn(c, remoteIP, remotePort, key)
		}(conn, ip, port, ipKey)
	}
}

func (s *Server) handleStreamConn(conn net.Conn, remoteIP net.IP, remotePort int, ipKey string) {
	if tc, ok := conn.(*tls.Conn); ok {
		hsCtx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
		err := tc.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			return
		}
	}

	buf := make([]byte, max(s.maxBytes, MinSTUNHeaderBytes))
	var req stun.Message
	var resp stun.Message

	for !s.closed.Load() {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		if _, err := io.ReadFull(conn, buf[:MinSTUNHeaderBytes]); err != nil {
			return
		}
		if !s.globalLim.Allow() || !s.ipLimiter.Allow(ipKey) {
			s.rateLimited.Add(1)
			return
		}

		// RFC 8489 Section 6: top two bits must be 00, magic cookie must be 0x2112A442,
		// and body length must be a multiple of 4 bytes.
		if buf[0]&0xC0 != 0 || binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
			s.malformedPackets.Add(1)
			return
		}
		bodyLen := int(binary.BigEndian.Uint16(buf[2:4]))
		if bodyLen%4 != 0 {
			s.malformedPackets.Add(1)
			return
		}
		totalLen := MinSTUNHeaderBytes + bodyLen
		if totalLen > s.maxBytes {
			s.oversizedPackets.Add(1)
			return
		}
		if bodyLen > 0 {
			if _, err := io.ReadFull(conn, buf[MinSTUNHeaderBytes:totalLen]); err != nil {
				return
			}
		}

		out, shouldReply := s.processMessage(&req, &resp, buf[:totalLen], remoteIP, remotePort)
		if !shouldReply {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
		if resp.Type == stun.BindingSuccess {
			s.bindingResps.Add(1)
		}
	}
}

func (s *Server) serveUDPLoop() {
	defer s.wg.Done()

	buf := make([]byte, s.maxBytes+1)
	var req stun.Message
	var resp stun.Message

	for !s.closed.Load() {
		n, raddr, err := s.udpConn.ReadFrom(buf)
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			s.log.Warn("stun read error", "err", err)
			continue
		}

		ip, port, ok := extractIPPort(raddr)
		if !ok {
			s.malformedPackets.Add(1)
			continue
		}

		ipKey := ip.String()
		if !s.globalLim.Allow() || !s.ipLimiter.Allow(ipKey) {
			s.rateLimited.Add(1)
			continue
		}

		if n > s.maxBytes {
			s.oversizedPackets.Add(1)
			continue
		}
		if n < MinSTUNHeaderBytes || !stun.IsMessage(buf[:n]) {
			s.malformedPackets.Add(1)
			continue
		}

		out, shouldReply := s.processMessage(&req, &resp, buf[:n], ip, port)
		if !shouldReply {
			continue
		}
		if _, err := s.udpConn.WriteTo(out, raddr); err == nil && resp.Type == stun.BindingSuccess {
			s.bindingResps.Add(1)
		}
	}
}

func (s *Server) processMessage(req, resp *stun.Message, raw []byte, remoteIP net.IP, remotePort int) ([]byte, bool) {
	req.Reset()
	if err := stun.Decode(raw, req); err != nil {
		s.malformedPackets.Add(1)
		return nil, false
	}

	// Indications never elicit responses in RFC 8489.
	if req.Type.Class == stun.ClassIndication {
		if req.Type.Method != stun.MethodBinding {
			s.unsupportedMethods.Add(1)
		}
		return nil, false
	}

	// Reject any non-Binding request (including TURN Allocate/Connect/etc.).
	if req.Type != stun.BindingRequest {
		s.unsupportedMethods.Add(1)
		if req.Type.Class == stun.ClassRequest {
			resp.Reset()
			errType := stun.NewType(req.Type.Method, stun.ClassErrorResponse)
			if buildErr := resp.Build(
				stun.NewTransactionIDSetter(req.TransactionID),
				errType,
				stun.CodeBadRequest,
				stun.Fingerprint,
			); buildErr == nil {
				return resp.Raw, true
			}
		}
		return nil, false
	}

	s.bindingReqs.Add(1)
	resp.Reset()
	if err := resp.Build(
		stun.NewTransactionIDSetter(req.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{
			IP:   remoteIP,
			Port: remotePort,
		},
		stun.Fingerprint,
	); err != nil {
		return nil, false
	}
	return resp.Raw, true
}

func extractIPPort(addr net.Addr) (net.IP, int, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if len(a.IP) > 0 && a.Port > 0 {
			return a.IP, a.Port, true
		}
	case *net.TCPAddr:
		if len(a.IP) > 0 && a.Port > 0 {
			return a.IP, a.Port, true
		}
	}
	if addr == nil {
		return nil, 0, false
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, false
	}
	return ip, port, true
}
