package hub

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lighthouse-in-snoo/pkg/identity"
)

var cgnatProxyPrefix = netip.MustParsePrefix("100.64.0.0/10")

const (
	tlsHandshakeRecordType = 0x16
	maxConcurrentPeeks     = 256
	peekFirstByteTimeout   = 5 * time.Second
)

type peekedConn struct {
	net.Conn
	first    byte
	hasFirst bool
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if c.hasFirst {
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = c.first
		c.hasFirst = false
		return 1, nil
	}
	return c.Conn.Read(p)
}

// tlsOrProxyListener serves direct TLS 1.3 connections alongside plaintext HTTP/WebSocket
// connections forwarded by TLS-terminating reverse proxies (such as Cloudtype, Nginx, Caddy,
// or Kubernetes Ingress) on private, loopback, link-local, or CGNAT network addresses.
// All TLS handshakes strictly enforce TLS 1.3; plaintext HTTP from public IPs is closed.
type tlsOrProxyListener struct {
	raw    net.Listener
	tlsCfg *tls.Config
	ready  chan net.Conn
	sem    chan struct{}
	done   chan struct{}
	closed atomic.Bool

	peekMu  sync.Mutex
	peeking map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func newTLSOrProxyListener(raw net.Listener, tlsCfg *tls.Config) *tlsOrProxyListener {
	l := &tlsOrProxyListener{
		raw:     raw,
		tlsCfg:  tlsCfg,
		ready:   make(chan net.Conn, 128),
		sem:     make(chan struct{}, maxConcurrentPeeks),
		done:    make(chan struct{}),
		peeking: make(map[net.Conn]struct{}),
	}
	l.wg.Add(1)
	go l.acceptLoop()
	return l
}

func (l *tlsOrProxyListener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.raw.Accept()
		if err != nil {
			if l.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-l.done:
				return
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}

		select {
		case l.sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}

		l.wg.Add(1)
		go l.classifyConn(conn)
	}
}

func (l *tlsOrProxyListener) classifyConn(conn net.Conn) {
	defer l.wg.Done()
	defer func() { <-l.sem }()

	l.peekMu.Lock()
	if l.closed.Load() {
		l.peekMu.Unlock()
		_ = conn.Close()
		return
	}
	l.peeking[conn] = struct{}{}
	l.peekMu.Unlock()

	_ = conn.SetReadDeadline(time.Now().Add(peekFirstByteTimeout))
	var first [1]byte
	n, err := io.ReadFull(conn, first[:])
	_ = conn.SetReadDeadline(time.Time{})

	l.peekMu.Lock()
	delete(l.peeking, conn)
	l.peekMu.Unlock()

	if err != nil || n != 1 || l.closed.Load() {
		_ = conn.Close()
		return
	}

	wrapped := &peekedConn{Conn: conn, first: first[0], hasFirst: true}
	var out net.Conn
	switch {
	case first[0] == tlsHandshakeRecordType:
		out = tls.Server(wrapped, l.tlsCfg)
	case isTrustedProxyAddr(conn.RemoteAddr()):
		out = wrapped
	default:
		_ = conn.Close()
		return
	}

	select {
	case l.ready <- out:
	case <-l.done:
		_ = out.Close()
	}
}

func (l *tlsOrProxyListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *tlsOrProxyListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.done)
	err := l.raw.Close()

	l.peekMu.Lock()
	for c := range l.peeking {
		_ = c.Close()
	}
	l.peekMu.Unlock()

	l.wg.Wait()
	for {
		select {
		case c := <-l.ready:
			_ = c.Close()
		default:
			return err
		}
	}
}

func (l *tlsOrProxyListener) Addr() net.Addr {
	return l.raw.Addr()
}

func isTrustedProxyAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host := extractRemoteIP(addr.String())
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnatProxyPrefix.Contains(ip)
}

func extractClientIP(r *http.Request) string {
	if r.TLS == nil {
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			if ip, err := netip.ParseAddr(realIP); err == nil {
				return ip.Unmap().String()
			}
		}
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
				return ip.Unmap().String()
			}
		}
	}
	return extractRemoteIP(r.RemoteAddr)
}

// resolveRequestOrigin returns the pinned hub origin when configured, or dynamically derives
// the canonical "wss://host[:port]" origin from the incoming HTTP/WebSocket request so hubs
// hosted behind rotating domains and random port forwards (e.g. Cloudtype) work with zero config.
func (s *Server) resolveRequestOrigin(r *http.Request) string {
	if s.hubOrigin != "" {
		return s.hubOrigin
	}
	host := strings.TrimSpace(r.Host)
	if r.TLS == nil {
		if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
			first, _, _ := strings.Cut(xfh, ",")
			if candidate := strings.TrimSpace(first); candidate != "" {
				host = candidate
			}
		}
		if host != "" {
			if _, _, err := net.SplitHostPort(host); err != nil {
				if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); xfp != "" {
					firstPort, _, _ := strings.Cut(xfp, ",")
					firstPort = strings.TrimSpace(firstPort)
					if p, pErr := strconv.Atoi(firstPort); pErr == nil && p >= 1 && p <= 65535 && p != 443 && p != 80 {
						host = net.JoinHostPort(strings.Trim(host, "[]"), firstPort)
					}
				}
			}
		}
	}
	if host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			host = "[" + host + "]"
		}
		if canon, err := identity.CanonicalizeOrigin("wss://" + host); err == nil {
			return canon
		}
	}
	if s.httpsListener != nil {
		if canon, err := identity.CanonicalizeOrigin("wss://" + s.httpsListener.Addr().String()); err == nil {
			return canon
		}
	}
	return "wss://localhost:8443"
}
