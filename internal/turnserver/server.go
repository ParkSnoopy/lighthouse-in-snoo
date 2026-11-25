package turnserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v4"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/logging"
	"github.com/pion/transport/v5"
	"github.com/pion/turn/v6"
)

const (
	// DefaultTURNSAddr is the standard RFC 7350 DTLS-over-UDP TURNS/STUNS port.
	DefaultTURNSAddr = ":5349"
	// DefaultInsecureTURNAddr is the standard plaintext UDP TURN port (opt-in only).
	DefaultInsecureTURNAddr = ":3478"
	// DefaultRealm is the default RFC 8656 TURN authentication realm.
	DefaultRealm = "lighthouse"
)

// ErrInsecureTURNProhibited is returned when plaintext TURN is configured without AllowInsecure.
var ErrInsecureTURNProhibited = errors.New("turnserver: plaintext TURN requires AllowInsecure=true; use encrypted TURNS")

// Config configures the integrated TURNS (DTLS 1.3 / UDP primary, TLS 1.3 / TCP fallback or TCP-only)
// and opt-in insecure plaintext UDP/TCP TURN server.
// Because pion/turn/v6 serves unauthenticated RFC 8489 STUN Binding requests alongside
// authenticated TURN allocations, a single encrypted :5349 listener handles both stuns: and turns:.
type Config struct {
	DTLSListenAddr string         // Primary UDP listen address for DTLS 1.3 TURNS/STUNS (default :5349).
	DTLSPacketConn net.PacketConn // Optional pre-bound UDP PacketConn wrapped with DTLS 1.3.
	TLSListenAddr  string         // TCP listen address for TLS 1.3 TURNS (?transport=tcp or TCP-only mode).
	TLSListener    net.Listener   // Optional pre-bound TCP listener wrapped with TLS 1.3.
	TLSConfig      *tls.Config    // Required for DTLS 1.3 / TLS 1.3 listeners.

	AllowInsecure bool           // Explicit opt-in required for plaintext UDP/TCP TURN.
	UDPListenAddr string         // Plaintext UDP listen address (requires AllowInsecure).
	UDPPacketConn net.PacketConn // Optional pre-bound plaintext UDP PacketConn (requires AllowInsecure).
	TCPListenAddr string         // Plaintext TCP listen address (requires AllowInsecure).
	TCPListener   net.Listener   // Optional pre-bound plaintext TCP listener (requires AllowInsecure).

	Realm            string
	SharedSecret     string            // Enables time-limited HMAC TURN REST credentials.
	Users            map[string]string // Optional static username -> password credentials.
	AuthHandler      turn.AuthHandler  // Optional custom AuthHandler override.
	PublicIP         net.IP            // Optional static public IP advertised in relay allocations.
	RelayBindAddress string            // Local bind IP for allocated UDP relay sockets.
	RelayMinPort     uint16            // Optional lower bound for allocated UDP relay ports.
	RelayMaxPort     uint16            // Optional upper bound for allocated UDP relay ports.
	RelayNet         transport.Net     // Optional custom transport.Net.
	LoggerFactory    logging.LoggerFactory
}

// Server wraps a Pion TURN server serving DTLS 1.3 / UDP or TLS 1.3 / TCP TURNS by default.
type Server struct {
	srv          *turn.Server
	dtlsAddr     net.Addr
	dtlsRawConn  net.PacketConn
	ownsDTLSConn bool
	tlsAddr      net.Addr
	udpAddr      net.Addr
	tcpAddr      net.Addr
	closed       atomic.Bool
}

// New creates and starts a TURNS (DTLS 1.3/UDP or TLS 1.3/TCP) and/or opt-in insecure TURN server.
func New(cfg Config) (*Server, error) {
	wantsPlainUDP := cfg.UDPListenAddr != "" || cfg.UDPPacketConn != nil
	wantsPlainTCP := cfg.TCPListenAddr != "" || cfg.TCPListener != nil
	if (wantsPlainUDP || wantsPlainTCP) && !cfg.AllowInsecure {
		return nil, ErrInsecureTURNProhibited
	}

	wantsTLS := cfg.TLSListenAddr != "" || cfg.TLSListener != nil
	wantsDTLS := cfg.DTLSListenAddr != "" || cfg.DTLSPacketConn != nil ||
		(cfg.TLSConfig != nil && !wantsPlainUDP && !wantsPlainTCP && !wantsTLS)
	if !wantsDTLS && !wantsTLS && !wantsPlainUDP && !wantsPlainTCP {
		return nil, errors.New("turnserver: TLSConfig is required for encrypted TURNS (or opt in with AllowInsecure)")
	}
	if (wantsDTLS || wantsTLS) && (cfg.TLSConfig == nil || len(cfg.TLSConfig.Certificates) == 0) {
		return nil, errors.New("turnserver: TLSConfig with certificate is required for DTLS/TLS TURNS")
	}

	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		realm = DefaultRealm
	}

	lf := cfg.LoggerFactory
	if lf == nil {
		dlf := logging.NewDefaultLoggerFactory()
		dlf.DefaultLogLevel = logging.LogLevelError
		lf = dlf
	}

	authHandler, err := buildAuthHandler(cfg, realm, lf)
	if err != nil {
		return nil, err
	}

	var (
		listeners    []turn.ListenerConfig
		udpConns     []turn.PacketConnConfig
		dtlsAddr     net.Addr
		dtlsRawConn  net.PacketConn
		ownsDTLSConn bool
		tlsAddr      net.Addr
		udpAddr      net.Addr
		tcpAddr      net.Addr
		ownedClosers []func() error
	)

	cleanupOwned := func() {
		for _, fn := range ownedClosers {
			_ = fn()
		}
	}

	if wantsDTLS {
		rawConn := cfg.DTLSPacketConn
		if rawConn == nil {
			addr := cfg.DTLSListenAddr
			if addr == "" {
				addr = DefaultTURNSAddr
			}
			rawConn, err = net.ListenPacket("udp", addr)
			if err != nil {
				cleanupOwned()
				return nil, fmt.Errorf("listen turns dtls/udp %s: %w", addr, err)
			}
			ownsDTLSConn = true
			ownedClosers = append(ownedClosers, rawConn.Close)
		}
		dtlsRawConn = rawConn

		dtlsLn, err := dtls.Listen(rawConn,
			dtls.WithCertificates(cfg.TLSConfig.Certificates...),
			dtls.WithMinVersion(dtlsProtocol.Version1_3),
			dtls.WithMaxVersion(dtlsProtocol.Version1_3),
			dtls.WithReplayProtectionWindow(64),
			dtls.WithFlightInterval(100*time.Millisecond),
			dtls.WithLoggerFactory(lf),
		)
		if err != nil {
			cleanupOwned()
			return nil, fmt.Errorf("start turns dtls listener: %w", err)
		}
		ownedClosers = append(ownedClosers, dtlsLn.Close)
		dtlsAddr = dtlsLn.Addr()

		listeners = append(listeners, turn.ListenerConfig{
			Listener:              dtlsLn,
			RelayAddressGenerator: buildRelayGenerator(cfg, dtlsAddr),
		})
	}

	if wantsTLS {
		tcfg := cfg.TLSConfig.Clone()
		tcfg.MinVersion = tls.VersionTLS13
		tcfg.MaxVersion = tls.VersionTLS13

		rawLn := cfg.TLSListener
		if rawLn == nil {
			rawLn, err = net.Listen("tcp", cfg.TLSListenAddr)
			if err != nil {
				cleanupOwned()
				return nil, fmt.Errorf("listen turns tls/tcp %s: %w", cfg.TLSListenAddr, err)
			}
		}
		tlsLn := tls.NewListener(rawLn, tcfg)
		ownedClosers = append(ownedClosers, tlsLn.Close)
		tlsAddr = tlsLn.Addr()

		listeners = append(listeners, turn.ListenerConfig{
			Listener:              tlsLn,
			RelayAddressGenerator: buildRelayGenerator(cfg, tlsAddr),
		})
	}

	if wantsPlainUDP {
		conn := cfg.UDPPacketConn
		if conn == nil {
			addr := cfg.UDPListenAddr
			if addr == "" {
				addr = DefaultInsecureTURNAddr
			}
			conn, err = net.ListenPacket("udp", addr)
			if err != nil {
				cleanupOwned()
				return nil, fmt.Errorf("listen insecure turn udp %s: %w", addr, err)
			}
			ownedClosers = append(ownedClosers, conn.Close)
		}
		udpAddr = conn.LocalAddr()
		udpConns = append(udpConns, turn.PacketConnConfig{
			PacketConn:            conn,
			RelayAddressGenerator: buildRelayGenerator(cfg, udpAddr),
		})
	}

	if wantsPlainTCP {
		tcpLn := cfg.TCPListener
		if tcpLn == nil {
			addr := cfg.TCPListenAddr
			if addr == "" {
				addr = DefaultInsecureTURNAddr
			}
			tcpLn, err = net.Listen("tcp", addr)
			if err != nil {
				cleanupOwned()
				return nil, fmt.Errorf("listen insecure turn tcp %s: %w", addr, err)
			}
		}
		ownedClosers = append(ownedClosers, tcpLn.Close)
		tcpAddr = tcpLn.Addr()
		listeners = append(listeners, turn.ListenerConfig{
			Listener:              tcpLn,
			RelayAddressGenerator: buildRelayGenerator(cfg, tcpAddr),
		})
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:             realm,
		AuthHandler:       authHandler,
		ListenerConfigs:   listeners,
		PacketConnConfigs: udpConns,
		LoggerFactory:     lf,
	})
	if err != nil {
		cleanupOwned()
		return nil, fmt.Errorf("start turn server: %w", err)
	}

	return &Server{
		srv:          srv,
		dtlsAddr:     dtlsAddr,
		dtlsRawConn:  dtlsRawConn,
		ownsDTLSConn: ownsDTLSConn,
		tlsAddr:      tlsAddr,
		udpAddr:      udpAddr,
		tcpAddr:      tcpAddr,
	}, nil
}

// ParseStaticUsers parses a comma-separated "user=pass,user2=pass2" list.
func ParseStaticUsers(raw string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for entry := range strings.SplitSeq(trimmed, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] == "" {
			return nil, fmt.Errorf("turnserver: invalid user credential %q (expected user=pass)", entry)
		}
		out[strings.TrimSpace(parts[0])] = parts[1]
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// GenerateCredentials issues time-limited TURN REST credentials compatible with SharedSecret.
func GenerateCredentials(sharedSecret, user string, ttl time.Duration) (username, password string, err error) {
	if strings.TrimSpace(sharedSecret) == "" {
		return "", "", errors.New("turnserver: shared secret is empty")
	}
	if user == "" {
		user = "peer"
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return turn.GenerateLongTermTURNRESTCredentials(sharedSecret, user, ttl)
}

func buildAuthHandler(cfg Config, realm string, lf logging.LoggerFactory) (turn.AuthHandler, error) {
	if cfg.AuthHandler != nil {
		return cfg.AuthHandler, nil
	}

	var restHandler turn.AuthHandler
	if strings.TrimSpace(cfg.SharedSecret) != "" {
		restHandler = turn.LongTermTURNRESTAuthHandler(cfg.SharedSecret, lf.NewLogger("turn"))
	}

	staticKeys := make(map[string][]byte, len(cfg.Users))
	for user, pass := range cfg.Users {
		if user == "" || pass == "" {
			return nil, errors.New("turnserver: static TURN username and password must be non-empty")
		}
		staticKeys[user] = turn.GenerateAuthKey(user, realm, pass)
	}

	if restHandler == nil && len(staticKeys) == 0 {
		return nil, errors.New("turnserver: SharedSecret, Users, or AuthHandler is required")
	}

	return func(ra *turn.RequestAttributes) (string, []byte, bool) {
		if key, ok := staticKeys[ra.Username]; ok {
			return ra.Username, key, true
		}
		if restHandler != nil {
			return restHandler(ra)
		}
		return "", nil, false
	}, nil
}

func buildRelayGenerator(cfg Config, boundAddr net.Addr) turn.RelayAddressGenerator {
	bindAddr := strings.TrimSpace(cfg.RelayBindAddress)
	if bindAddr == "" {
		bindAddr = defaultBindIPFromAddr(boundAddr)
	}
	if cfg.PublicIP != nil {
		if cfg.RelayMinPort > 0 && cfg.RelayMaxPort >= cfg.RelayMinPort {
			return &turn.RelayAddressGeneratorPortRange{
				RelayAddress: cfg.PublicIP,
				Address:      bindAddr,
				MinPort:      cfg.RelayMinPort,
				MaxPort:      cfg.RelayMaxPort,
				Net:          cfg.RelayNet,
			}
		}
		return &turn.RelayAddressGeneratorStatic{
			RelayAddress: cfg.PublicIP,
			Address:      bindAddr,
			Net:          cfg.RelayNet,
		}
	}
	return &turn.RelayAddressGeneratorNone{
		Address: bindAddr,
		Net:     cfg.RelayNet,
	}
}

func defaultBindIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return "0.0.0.0"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "0.0.0.0"
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return "0.0.0.0"
	}
	return ip.String()
}

// DTLSAddr returns the bound DTLS 1.3 / UDP TURNS address, or nil if disabled.
func (s *Server) DTLSAddr() net.Addr {
	return s.dtlsAddr
}

// TLSAddr returns the optional TLS 1.3 / TCP TURNS address, or nil if disabled.
func (s *Server) TLSAddr() net.Addr {
	return s.tlsAddr
}

// UDPAddr returns the bound plaintext UDP TURN address, or nil if disabled.
func (s *Server) UDPAddr() net.Addr {
	return s.udpAddr
}

// TCPAddr returns the bound plaintext TCP TURN address, or nil if disabled.
func (s *Server) TCPAddr() net.Addr {
	return s.tcpAddr
}

// AllocationCount returns the current number of active TURN relay allocations.
func (s *Server) AllocationCount() int {
	if s.srv == nil {
		return 0
	}
	return s.srv.AllocationCount()
}

// Close shuts down the TURN/TURNS server and releases all active allocations and sockets.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	var srvErr, rawErr error
	if s.srv != nil {
		srvErr = s.srv.Close()
	}
	if s.dtlsRawConn != nil && !s.ownsDTLSConn {
		_ = s.dtlsRawConn.SetReadDeadline(time.Now())
	} else if s.dtlsRawConn != nil && s.ownsDTLSConn {
		if err := s.dtlsRawConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			rawErr = err
		}
	}
	return errors.Join(srvErr, rawErr)
}
