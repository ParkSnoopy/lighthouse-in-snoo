package stunserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v5"
	"golang.org/x/time/rate"

	"lighthouse-in-snoo/internal/ratelimit"
)

const (
	// MinSTUNHeaderBytes is the fixed 20-byte RFC 8489 STUN header length.
	MinSTUNHeaderBytes = 20
	// DefaultMaxDatagramBytes bounds incoming UDP datagrams accepted by the STUN Binding service.
	DefaultMaxDatagramBytes = 576
)

// Config configures the UDP-only RFC 8489 STUN Binding server (Section 8).
type Config struct {
	ListenAddr       string
	PacketConn       net.PacketConn // Optional pre-bound UDP PacketConn (e.g. vnet or custom socket).
	MaxDatagramBytes int
	PerIPRPS         float64
	PerIPBurst       int
	MaxTrackedIPs    int
	GlobalRPS        float64
	GlobalBurst      int
	Logger           *slog.Logger
}

// Stats exposes aggregate non-sensitive STUN operational counters (Section 9).
type Stats struct {
	BindingRequests    uint64
	BindingResponses   uint64
	UnsupportedMethods uint64
	MalformedPackets   uint64
	OversizedPackets   uint64
	RateLimited        uint64
}

// Server implements a minimal UDP-only RFC 8489 STUN Binding responder returning
// XOR-MAPPED-ADDRESS without any TURN allocation or packet forwarding capability.
type Server struct {
	conn      net.PacketConn
	ownsConn  bool
	maxBytes  int
	ipLimiter *ratelimit.KeyedLimiter
	globalLim *rate.Limiter
	log       *slog.Logger
	closed    atomic.Bool
	wg        sync.WaitGroup

	bindingReqs        atomic.Uint64
	bindingResps       atomic.Uint64
	unsupportedMethods atomic.Uint64
	malformedPackets   atomic.Uint64
	oversizedPackets   atomic.Uint64
	rateLimited        atomic.Uint64
}

// New creates and starts a UDP-only STUN Binding server.
func New(cfg Config) (*Server, error) {
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
	globalRPS := cfg.GlobalRPS
	if globalRPS <= 0 {
		globalRPS = 5000
	}
	globalBurst := cfg.GlobalBurst
	if globalBurst <= 0 {
		globalBurst = 10000
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	conn := cfg.PacketConn
	ownsConn := false
	if conn == nil {
		addr := cfg.ListenAddr
		if addr == "" {
			addr = ":3478"
		}
		var err error
		conn, err = net.ListenPacket("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("listen stun udp %s: %w", addr, err)
		}
		ownsConn = true
	}

	s := &Server{
		conn:      conn,
		ownsConn:  ownsConn,
		maxBytes:  maxBytes,
		ipLimiter: ratelimit.NewKeyedLimiter(perIPRPS, perIPBurst, maxIPs, 5*time.Minute),
		globalLim: rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
		log:       logger,
	}
	s.wg.Add(1)
	go s.serveLoop()
	return s, nil
}

// LocalAddr returns the bound UDP socket address.
func (s *Server) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// Stats returns a snapshot of aggregate STUN counters.
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

// Close shuts down the STUN UDP server cleanly.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	var err error
	if s.ownsConn {
		err = s.conn.Close()
	} else {
		_ = s.conn.SetReadDeadline(time.Now())
	}
	s.wg.Wait()
	return err
}

func (s *Server) serveLoop() {
	defer s.wg.Done()

	// Read 1 extra byte beyond maxBytes to detect oversized UDP datagrams cleanly.
	buf := make([]byte, s.maxBytes+1)
	var req stun.Message
	var resp stun.Message

	for !s.closed.Load() {
		n, raddr, err := s.conn.ReadFrom(buf)
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

		udpAddr, ok := extractUDPAddr(raddr)
		if !ok {
			s.malformedPackets.Add(1)
			continue
		}

		ipKey := udpAddr.IP.String()
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

		req.Reset()
		if err := stun.Decode(buf[:n], &req); err != nil {
			s.malformedPackets.Add(1)
			continue
		}

		// Indications never elicit responses in RFC 8489.
		if req.Type.Class == stun.ClassIndication {
			if req.Type.Method != stun.MethodBinding {
				s.unsupportedMethods.Add(1)
			}
			continue
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
					_, _ = s.conn.WriteTo(resp.Raw, raddr)
				}
			}
			continue
		}

		s.bindingReqs.Add(1)
		resp.Reset()
		if err := resp.Build(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{
				IP:   udpAddr.IP,
				Port: udpAddr.Port,
			},
			stun.Fingerprint,
		); err != nil {
			continue
		}
		if _, err := s.conn.WriteTo(resp.Raw, raddr); err == nil {
			s.bindingResps.Add(1)
		}
	}
}

func extractUDPAddr(addr net.Addr) (*net.UDPAddr, bool) {
	if u, ok := addr.(*net.UDPAddr); ok && len(u.IP) > 0 && u.Port > 0 {
		return u, true
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port <= 0 || port > 65535 {
		return nil, false
	}
	return &net.UDPAddr{IP: ip, Port: port}, true
}
