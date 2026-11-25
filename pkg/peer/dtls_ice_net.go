package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v4"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/logging"
	"github.com/pion/stun/v5"
	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
)

// dtls13TransportNet wraps a transport.Net so all STUNS and TURNS UDP traffic
// to configured secure endpoints runs over strict DTLS 1.3 / UDP (RFC 7350 + RFC 9147)
// on the exact same local UDP socket used by ICE for NAT hole-punching and direct peer traffic.
type dtls13TransportNet struct {
	transport.Net

	rootCAs       *x509.CertPool
	loggerFactory logging.LoggerFactory

	mu            sync.RWMutex
	targetsByHost map[string]string         // "host:port" -> serverName
	targetsByAddr map[netip.AddrPort]string // canonical ip:port -> serverName
}

func newDTLS13TransportNet(
	base transport.Net,
	dtlsTargets map[string]string,
	tlsCfg *tls.Config,
	lf logging.LoggerFactory,
) (*dtls13TransportNet, error) {
	if base == nil {
		var err error
		base, err = stdnet.NewNet()
		if err != nil {
			return nil, fmt.Errorf("peer: init stdnet: %w", err)
		}
	}
	var roots *x509.CertPool
	if tlsCfg != nil && tlsCfg.RootCAs != nil {
		roots = tlsCfg.RootCAs
	}
	if lf == nil {
		dlf := logging.NewDefaultLoggerFactory()
		dlf.DefaultLogLevel = logging.LogLevelError
		lf = dlf
	}

	n := &dtls13TransportNet{
		Net:           base,
		rootCAs:       roots,
		loggerFactory: lf,
		targetsByHost: make(map[string]string, len(dtlsTargets)),
		targetsByAddr: make(map[netip.AddrPort]string, len(dtlsTargets)),
	}
	for hostPort, serverName := range dtlsTargets {
		n.targetsByHost[hostPort] = serverName
		if ap, ok := parseCanonicalAddrPort(hostPort); ok {
			n.targetsByAddr[ap] = serverName
		}
	}
	return n, nil
}

func (n *dtls13TransportNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	resolved, err := n.Net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	n.mu.RLock()
	serverName, ok := n.targetsByHost[address]
	n.mu.RUnlock()
	if ok && resolved != nil {
		if ap, apOK := addrToCanonicalAddrPort(resolved); apOK {
			n.mu.Lock()
			n.targetsByAddr[ap] = serverName
			n.mu.Unlock()
		}
	}
	return resolved, nil
}

func (n *dtls13TransportNet) lookupTarget(addr net.Addr) (string, bool) {
	if addr == nil {
		return "", false
	}
	if ap, ok := addrToCanonicalAddrPort(addr); ok {
		n.mu.RLock()
		sn, found := n.targetsByAddr[ap]
		n.mu.RUnlock()
		if found {
			return sn, true
		}
	}
	n.mu.RLock()
	sn, found := n.targetsByHost[addr.String()]
	n.mu.RUnlock()
	return sn, found
}

func (n *dtls13TransportNet) ListenPacket(network, address string) (net.PacketConn, error) {
	raw, err := n.Net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return newDTLS13PacketConn(raw, n), nil
}

func (n *dtls13TransportNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	raw, err := n.Net.ListenUDP(network, locAddr)
	if err != nil {
		return nil, err
	}
	return &dtls13UDPConn{
		UDPConn:          raw,
		dtls13PacketConn: newDTLS13PacketConn(raw, n),
	}, nil
}

type inboundDatagram struct {
	data []byte
	addr net.Addr
}

type dtlsSessionState struct {
	mu        sync.Mutex
	readyCh   chan struct{}
	closedCh  chan struct{}
	closeOnce sync.Once
	closed    bool
	rawIn     chan []byte
	conn      *dtls.Conn
	dialErr   error
}

func (s *dtlsSessionState) setConn(c *dtls.Conn) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		return false
	}
	s.conn = c
	s.mu.Unlock()
	return true
}

func (s *dtlsSessionState) getConn() *dtls.Conn {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	return c
}

func (s *dtlsSessionState) closeSession() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		c := s.conn
		s.mu.Unlock()
		close(s.closedCh)
		if c != nil {
			_ = c.Close()
		}
	})
}

type dtls13PacketConn struct {
	raw   net.PacketConn
	owner *dtls13TransportNet

	appIn     chan inboundDatagram
	closedCh  chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once

	dlMu         sync.Mutex
	readDeadline time.Time
	dlNotify     chan struct{}

	sessMu   sync.Mutex
	sessions map[netip.AddrPort]*dtlsSessionState
}

func newDTLS13PacketConn(raw net.PacketConn, owner *dtls13TransportNet) *dtls13PacketConn {
	p := &dtls13PacketConn{
		raw:      raw,
		owner:    owner,
		appIn:    make(chan inboundDatagram, 256),
		closedCh: make(chan struct{}),
		dlNotify: make(chan struct{}, 1),
		sessions: make(map[netip.AddrPort]*dtlsSessionState),
	}
	go p.rawReadLoop()
	return p
}

func (p *dtls13PacketConn) rawReadLoop() {
	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := p.raw.ReadFrom(buf)
		if err != nil {
			p.closeInternal()
			return
		}
		if n <= 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)

		if ap, ok := addrToCanonicalAddrPort(srcAddr); ok {
			p.sessMu.Lock()
			sess := p.sessions[ap]
			p.sessMu.Unlock()
			if sess != nil {
				select {
				case sess.rawIn <- pkt:
				case <-sess.closedCh:
				case <-p.closedCh:
					return
				default:
				}
				continue
			}
		}

		select {
		case p.appIn <- inboundDatagram{data: pkt, addr: srcAddr}:
		case <-p.closedCh:
			return
		default:
		}
	}
}

func (p *dtls13PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		// Check immediate availability first.
		select {
		case msg := <-p.appIn:
			n := copy(b, msg.data)
			return n, msg.addr, nil
		default:
		}

		if p.closed.Load() {
			return 0, nil, net.ErrClosed
		}

		p.dlMu.Lock()
		dl := p.readDeadline
		p.dlMu.Unlock()

		var timer *time.Timer
		var timerCh <-chan time.Time
		if !dl.IsZero() {
			wait := time.Until(dl)
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timerCh = timer.C
		}

		select {
		case msg := <-p.appIn:
			if timer != nil {
				timer.Stop()
			}
			n := copy(b, msg.data)
			return n, msg.addr, nil
		case <-p.dlNotify:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timerCh:
			return 0, nil, os.ErrDeadlineExceeded
		case <-p.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		}
	}
}

func (p *dtls13PacketConn) WriteTo(payload []byte, dst net.Addr) (int, error) {
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	serverName, isDTLS := p.owner.lookupTarget(dst)
	if !isDTLS {
		return p.raw.WriteTo(payload, dst)
	}

	sess, err := p.getOrDialDTLSSession(dst, serverName)
	if err != nil {
		return 0, err
	}
	conn := sess.getConn()
	if conn == nil {
		return 0, net.ErrClosed
	}
	n, err := conn.Write(payload)
	if err != nil {
		p.dropSession(dst, sess)
		return 0, err
	}
	return n, nil
}

func (p *dtls13PacketConn) getOrDialDTLSSession(dst net.Addr, serverName string) (*dtlsSessionState, error) {
	ap, ok := addrToCanonicalAddrPort(dst)
	if !ok {
		return nil, fmt.Errorf("peer: invalid DTLS UDP target %v", dst)
	}

	p.sessMu.Lock()
	if p.closed.Load() {
		p.sessMu.Unlock()
		return nil, net.ErrClosed
	}
	if existing, exists := p.sessions[ap]; exists {
		p.sessMu.Unlock()
		select {
		case <-existing.readyCh:
			if existing.dialErr != nil {
				return nil, existing.dialErr
			}
			return existing, nil
		case <-p.closedCh:
			return nil, net.ErrClosed
		}
	}

	sess := &dtlsSessionState{
		readyCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
		rawIn:    make(chan []byte, 128),
	}
	p.sessions[ap] = sess
	p.sessMu.Unlock()

	subConn := &dtlsSubPacketConn{
		parentRaw:  p.raw,
		remoteAddr: dst,
		rawIn:      sess.rawIn,
		closedCh:   sess.closedCh,
		dlNotify:   make(chan struct{}, 1),
	}

	opts := []dtls.ClientOption{
		dtls.WithMinVersion(dtlsProtocol.Version1_3),
		dtls.WithMaxVersion(dtlsProtocol.Version1_3),
		dtls.WithServerName(serverName),
		// Full X.509 chain, EKU, hostname/IP SAN, and modern signature verification is performed
		// in verifyDTLSServerCertChain (working around pion/dtls/v4@v4.0.1's PureEd25519 CA bug).
		dtls.WithInsecureSkipVerify(true),
		dtls.WithVerifyPeerCertificate(func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyDTLSServerCertChain(rawCerts, p.owner.rootCAs, serverName)
		}),
		dtls.WithReplayProtectionWindow(64),
		dtls.WithFlightInterval(100 * time.Millisecond),
		dtls.WithLoggerFactory(p.owner.loggerFactory),
	}

	dtlsConn, err := dtls.Client(subConn, dst, opts...)
	if err == nil {
		hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		go func() {
			select {
			case <-p.closedCh:
				cancel()
			case <-hsCtx.Done():
			}
		}()
		err = dtlsConn.HandshakeContext(hsCtx)
		cancel()
	}

	if err != nil {
		if dtlsConn != nil {
			_ = dtlsConn.Close()
		}
		sess.dialErr = fmt.Errorf("peer: DTLS 1.3 ICE server handshake (%s) failed: %w", serverName, err)
		sess.closeSession()
		p.sessMu.Lock()
		if p.sessions[ap] == sess {
			delete(p.sessions, ap)
		}
		p.sessMu.Unlock()
		close(sess.readyCh)
		return nil, sess.dialErr
	}

	if !sess.setConn(dtlsConn) {
		sess.dialErr = net.ErrClosed
		p.sessMu.Lock()
		if p.sessions[ap] == sess {
			delete(p.sessions, ap)
		}
		p.sessMu.Unlock()
		close(sess.readyCh)
		return nil, net.ErrClosed
	}
	close(sess.readyCh)
	go p.dtlsSessionReadLoop(ap, dst, sess, dtlsConn)
	return sess, nil
}

func (p *dtls13PacketConn) dtlsSessionReadLoop(ap netip.AddrPort, remoteAddr net.Addr, sess *dtlsSessionState, conn *dtls.Conn) {
	defer func() {
		sess.closeSession()
		p.sessMu.Lock()
		if p.sessions[ap] == sess {
			delete(p.sessions, ap)
		}
		p.sessMu.Unlock()
	}()

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case p.appIn <- inboundDatagram{data: pkt, addr: remoteAddr}:
		case <-sess.closedCh:
			return
		case <-p.closedCh:
			return
		}
	}
}

func (p *dtls13PacketConn) dropSession(dst net.Addr, sess *dtlsSessionState) {
	sess.closeSession()
	if ap, ok := addrToCanonicalAddrPort(dst); ok {
		p.sessMu.Lock()
		if p.sessions[ap] == sess {
			delete(p.sessions, ap)
		}
		p.sessMu.Unlock()
	}
}

func (p *dtls13PacketConn) closeInternal() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		close(p.closedCh)
		p.sessMu.Lock()
		sessions := make([]*dtlsSessionState, 0, len(p.sessions))
		for k, s := range p.sessions {
			sessions = append(sessions, s)
			delete(p.sessions, k)
		}
		p.sessMu.Unlock()
		for _, s := range sessions {
			s.closeSession()
		}
	})
}

func (p *dtls13PacketConn) Close() error {
	p.closeInternal()
	return p.raw.Close()
}

func (p *dtls13PacketConn) LocalAddr() net.Addr {
	return p.raw.LocalAddr()
}

func (p *dtls13PacketConn) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}

func (p *dtls13PacketConn) SetReadDeadline(t time.Time) error {
	p.dlMu.Lock()
	p.readDeadline = t
	p.dlMu.Unlock()
	select {
	case p.dlNotify <- struct{}{}:
	default:
	}
	return nil
}

func (p *dtls13PacketConn) SetWriteDeadline(t time.Time) error {
	return p.raw.SetWriteDeadline(t)
}

// dtls13UDPConn satisfies transport.UDPConn while routing ReadFrom*/WriteTo* through dtls13PacketConn.
type dtls13UDPConn struct {
	transport.UDPConn
	*dtls13PacketConn
}

func (u *dtls13UDPConn) Close() error                  { return u.dtls13PacketConn.Close() }
func (u *dtls13UDPConn) LocalAddr() net.Addr           { return u.dtls13PacketConn.LocalAddr() }
func (u *dtls13UDPConn) SetDeadline(t time.Time) error { return u.dtls13PacketConn.SetDeadline(t) }
func (u *dtls13UDPConn) SetReadDeadline(t time.Time) error {
	return u.dtls13PacketConn.SetReadDeadline(t)
}
func (u *dtls13UDPConn) SetWriteDeadline(t time.Time) error {
	return u.dtls13PacketConn.SetWriteDeadline(t)
}
func (u *dtls13UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return u.dtls13PacketConn.ReadFrom(p)
}
func (u *dtls13UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return u.dtls13PacketConn.WriteTo(p, addr)
}
func (u *dtls13UDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := u.dtls13PacketConn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		return n, ua, nil
	}
	return n, nil, errors.New("peer: non-UDP source address")
}
func (u *dtls13UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return u.dtls13PacketConn.WriteTo(b, addr)
}

// dtlsSubPacketConn feeds demultiplexed UDP datagrams for one STUNS/TURNS server into dtls.Client
// without closing the shared parent UDP socket when the DTLS session ends.
type dtlsSubPacketConn struct {
	parentRaw  net.PacketConn
	remoteAddr net.Addr
	rawIn      <-chan []byte
	closedCh   <-chan struct{}

	dlMu         sync.Mutex
	readDeadline time.Time
	dlNotify     chan struct{}
}

func (s *dtlsSubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case pkt := <-s.rawIn:
			return copy(p, pkt), s.remoteAddr, nil
		default:
		}

		s.dlMu.Lock()
		dl := s.readDeadline
		s.dlMu.Unlock()

		var timer *time.Timer
		var timerCh <-chan time.Time
		if !dl.IsZero() {
			wait := time.Until(dl)
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timerCh = timer.C
		}

		select {
		case pkt := <-s.rawIn:
			if timer != nil {
				timer.Stop()
			}
			return copy(p, pkt), s.remoteAddr, nil
		case <-s.dlNotify:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timerCh:
			return 0, nil, os.ErrDeadlineExceeded
		case <-s.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		}
	}
}

func (s *dtlsSubPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		addr = s.remoteAddr
	}
	return s.parentRaw.WriteTo(p, addr)
}

func (s *dtlsSubPacketConn) Close() error        { return nil }
func (s *dtlsSubPacketConn) LocalAddr() net.Addr { return s.parentRaw.LocalAddr() }
func (s *dtlsSubPacketConn) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}
func (s *dtlsSubPacketConn) SetReadDeadline(t time.Time) error {
	s.dlMu.Lock()
	s.readDeadline = t
	s.dlMu.Unlock()
	select {
	case s.dlNotify <- struct{}{}:
	default:
	}
	return nil
}
func (s *dtlsSubPacketConn) SetWriteDeadline(t time.Time) error {
	return s.parentRaw.SetWriteDeadline(t)
}

// turnTCPProxyDialer enforces TLS 1.3 and custom RootCAs when an explicit turns:?transport=tcp
// URI is configured, while passing through plaintext turn:?transport=tcp only under --insecure.
type turnTCPProxyDialer struct {
	tlsHosts map[string]string // "host:port" -> serverName
	tlsCfg   *tls.Config
}

func (d *turnTCPProxyDialer) Dial(network, addr string) (net.Conn, error) {
	rawConn, err := net.DialTimeout(network, addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	serverName, useTLS := d.tlsHosts[addr]
	if !useTLS {
		return rawConn, nil
	}
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
	if d.tlsCfg != nil {
		tcfg = d.tlsCfg.Clone()
		tcfg.MinVersion = tls.VersionTLS13
		tcfg.MaxVersion = tls.VersionTLS13
		tcfg.ServerName = serverName
	}
	tlsConn := tls.Client(rawConn, tcfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// probeSTUNSOverDTLS13 performs an explicit RFC 7350 / RFC 8489 STUN Binding probe
// over DTLS 1.3 / UDP to verify reachability, server certificate trust, and observed mapping.
func probeSTUNSOverDTLS13(
	ctx context.Context,
	uri *stun.URI,
	baseNet transport.Net,
	tlsCfg *tls.Config,
	lf logging.LoggerFactory,
) (*stun.XORMappedAddress, error) {
	if uri == nil {
		return nil, errors.New("peer: no STUNS/TURNS URI configured")
	}
	if baseNet == nil {
		var err error
		baseNet, err = stdnet.NewNet()
		if err != nil {
			return nil, err
		}
	}
	if lf == nil {
		dlf := logging.NewDefaultLoggerFactory()
		dlf.DefaultLogLevel = logging.LogLevelError
		lf = dlf
	}

	targetAddr := net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port))
	raddr, err := baseNet.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	bindAddr := "0.0.0.0:0"
	if raddr.IP.To4() == nil {
		network = "udp6"
		bindAddr = "[::]:0"
	}
	rawConn, err := baseNet.ListenPacket(network, bindAddr)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	var roots *x509.CertPool
	if tlsCfg != nil && tlsCfg.RootCAs != nil {
		roots = tlsCfg.RootCAs
	}
	opts := []dtls.ClientOption{
		dtls.WithMinVersion(dtlsProtocol.Version1_3),
		dtls.WithMaxVersion(dtlsProtocol.Version1_3),
		dtls.WithServerName(uri.Host),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithVerifyPeerCertificate(func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyDTLSServerCertChain(rawCerts, roots, uri.Host)
		}),
		dtls.WithReplayProtectionWindow(64),
		dtls.WithFlightInterval(100 * time.Millisecond),
		dtls.WithLoggerFactory(lf),
	}

	dtlsConn, err := dtls.Client(rawConn, raddr, opts...)
	if err != nil {
		return nil, err
	}
	defer dtlsConn.Close()

	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = dtlsConn.SetDeadline(dl)
	}

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if _, err := dtlsConn.Write(req.Raw); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := dtlsConn.Read(buf)
	if err != nil {
		return nil, err
	}
	var resp stun.Message
	if err := stun.Decode(buf[:n], &resp); err != nil {
		return nil, err
	}
	if resp.Type != stun.BindingSuccess || resp.TransactionID != req.TransactionID {
		return nil, fmt.Errorf("peer: unexpected STUNS response %v", resp.Type)
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(&resp); err != nil {
		return nil, err
	}
	return &mapped, nil
}

// verifyDTLSServerCertChain enforces strict Go crypto/x509 server certificate verification
// (root CA chain, intermediates, validity window, ServerAuth EKU, DNS/IP SAN matching, and
// modern non-SHA1/MD5 certificate signatures including PureEd25519 CAs).
func verifyDTLSServerCertChain(rawCerts [][]byte, roots *x509.CertPool, serverName string) error {
	if len(rawCerts) == 0 {
		return errors.New("peer: DTLS server presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, der := range rawCerts {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("peer: parse DTLS server certificate: %w", err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, ic := range certs[1:] {
		intermediates.AddCert(ic)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}
	for _, chain := range chains {
		valid := true
		for i := 0; i < len(chain)-1; i++ {
			if !isAllowedCertSignatureAlgorithm(chain[i].SignatureAlgorithm) {
				valid = false
				break
			}
		}
		if valid {
			return nil
		}
	}
	return errors.New("peer: DTLS server certificate chain uses disallowed signature algorithm")
}

func isAllowedCertSignatureAlgorithm(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.PureEd25519,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return true
	default:
		return false
	}
}

func parseCanonicalAddrPort(hostPort string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func addrToCanonicalAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if ua, ok := addr.(*net.UDPAddr); ok && ua != nil {
		ap := ua.AddrPort()
		if ap.IsValid() {
			return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
		}
	}
	return parseCanonicalAddrPort(addr.String())
}
