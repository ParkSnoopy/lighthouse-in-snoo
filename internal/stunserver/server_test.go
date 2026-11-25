package stunserver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/stun/v5"

	"lighthouse-in-snoo/internal/stunserver"
)

func makeTestSTUNSCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}, pool
}

func TestSTUNSDTLS13UDPDefaultAndInsecureOptIn(t *testing.T) {
	t.Parallel()

	t.Run("Rejects plaintext UDP without AllowInsecure", func(t *testing.T) {
		t.Parallel()
		_, err := stunserver.New(stunserver.Config{
			ListenAddr: "127.0.0.1:0",
		})
		if !errors.Is(err, stunserver.ErrInsecureSTUNProhibited) {
			t.Fatalf("expected ErrInsecureSTUNProhibited, got %v", err)
		}
	})

	t.Run("DTLS 1.3 UDP STUNS IPv4 binding, DTLS 1.2 rejected, TURN allocate rejected", func(t *testing.T) {
		t.Parallel()
		srvTLS, roots := makeTestSTUNSCert(t)
		srv, err := stunserver.New(stunserver.Config{
			DTLSListenAddr: "127.0.0.1:0",
			TLSConfig:      srvTLS,
			PerIPRPS:       200,
			PerIPBurst:     400,
		})
		if err != nil {
			t.Fatalf("start stuns server: %v", err)
		}
		defer srv.Close()

		// DTLS 1.2 client MUST be rejected.
		raw12, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		dtls12, err := dtls.Client(raw12, srv.DTLSAddr(),
			dtls.WithRootCAs(roots),
			dtls.WithServerName("127.0.0.1"),
			dtls.WithMinVersion(dtlsProtocol.Version1_2),
			dtls.WithMaxVersion(dtlsProtocol.Version1_2),
			dtls.WithFlightInterval(100*time.Millisecond),
		)
		if err != nil {
			_ = raw12.Close()
			t.Fatal(err)
		}
		ctx12, cancel12 := context.WithTimeout(context.Background(), 800*time.Millisecond)
		if hsErr := dtls12.HandshakeContext(ctx12); hsErr == nil {
			cancel12()
			_ = dtls12.Close()
			_ = raw12.Close()
			t.Fatal("expected DTLS 1.2 handshake to STUNS server to fail")
		}
		cancel12()
		_ = dtls12.Close()
		_ = raw12.Close()

		// DTLS 1.3 client succeeds and gets XOR-MAPPED-ADDRESS matching its UDP socket.
		raw13, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer raw13.Close()

		dtls13, err := dtls.Client(raw13, srv.DTLSAddr(),
			dtls.WithRootCAs(roots),
			dtls.WithServerName("127.0.0.1"),
			dtls.WithMinVersion(dtlsProtocol.Version1_3),
			dtls.WithMaxVersion(dtlsProtocol.Version1_3),
			dtls.WithFlightInterval(100*time.Millisecond),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer dtls13.Close()

		hsCtx, hsCancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := dtls13.HandshakeContext(hsCtx); err != nil {
			hsCancel()
			t.Fatalf("DTLS 1.3 handshake failed: %v", err)
		}
		hsCancel()
		_ = dtls13.SetDeadline(time.Now().Add(3 * time.Second))

		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
		if _, err := dtls13.Write(req.Raw); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, err := dtls13.Read(buf)
		if err != nil {
			t.Fatalf("Read binding response: %v", err)
		}
		var resp stun.Message
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatalf("Decode response: %v", err)
		}
		if resp.Type != stun.BindingSuccess {
			t.Fatalf("got %v, want BindingSuccess", resp.Type)
		}
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(&resp); err != nil {
			t.Fatalf("GetFrom XORMappedAddress: %v", err)
		}
		localUDP := raw13.LocalAddr().(*net.UDPAddr)
		if !xorAddr.IP.Equal(localUDP.IP) || xorAddr.Port != localUDP.Port {
			t.Fatalf("mapped addr = %s:%d; want %s:%d", xorAddr.IP, xorAddr.Port, localUDP.IP, localUDP.Port)
		}

		// TURN Allocate over DTLS 1.3 STUNS-only server MUST return ErrorResponse.
		allocReq := stun.MustBuild(stun.TransactionID, stun.NewType(stun.MethodAllocate, stun.ClassRequest), stun.Fingerprint)
		if _, err := dtls13.Write(allocReq.Raw); err != nil {
			t.Fatal(err)
		}
		n, err = dtls13.Read(buf)
		if err != nil {
			t.Fatalf("Read allocate error: %v", err)
		}
		resp.Reset()
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Type.Class != stun.ClassErrorResponse {
			t.Fatalf("expected ClassErrorResponse for TURN Allocate, got %v", resp.Type)
		}

		st := srv.Stats()
		if st.BindingResponses != 1 || st.UnsupportedMethods != 1 {
			t.Fatalf("unexpected STUNS stats: %+v", st)
		}
	})

	t.Run("DTLS 1.3 UDP STUNS IPv6 binding", func(t *testing.T) {
		t.Parallel()
		lnConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		srvTLS, roots := makeTestSTUNSCert(t)
		srv, err := stunserver.New(stunserver.Config{
			DTLSPacketConn: lnConn,
			TLSConfig:      srvTLS,
		})
		if err != nil {
			_ = lnConn.Close()
			t.Fatal(err)
		}
		defer func() {
			_ = srv.Close()
			_ = lnConn.Close()
		}()

		c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer c6.Close()

		dc, err := dtls.Client(c6, srv.DTLSAddr(),
			dtls.WithRootCAs(roots),
			dtls.WithServerName("::1"),
			dtls.WithMinVersion(dtlsProtocol.Version1_3),
			dtls.WithMaxVersion(dtlsProtocol.Version1_3),
			dtls.WithFlightInterval(100*time.Millisecond),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer dc.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := dc.HandshakeContext(ctx); err != nil {
			t.Fatalf("IPv6 DTLS 1.3 handshake failed: %v", err)
		}
		_ = dc.SetDeadline(time.Now().Add(3 * time.Second))

		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := dc.Write(req.Raw); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, err := dc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var resp stun.Message
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatal(err)
		}
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(&resp); err != nil {
			t.Fatal(err)
		}
		localUDP := c6.LocalAddr().(*net.UDPAddr)
		if !xorAddr.IP.Equal(localUDP.IP) || xorAddr.Port != localUDP.Port {
			t.Fatalf("ipv6 mapped = [%s]:%d; want [%s]:%d", xorAddr.IP, xorAddr.Port, localUDP.IP, localUDP.Port)
		}
	})

	t.Run("Opt-in AllowInsecure plaintext UDP binding and validation", func(t *testing.T) {
		t.Parallel()
		srv, err := stunserver.New(stunserver.Config{
			AllowInsecure: true,
			ListenAddr:    "127.0.0.1:0",
			PerIPRPS:      100,
			PerIPBurst:    200,
		})
		if err != nil {
			t.Fatalf("start insecure stun server: %v", err)
		}
		defer srv.Close()

		clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer clientConn.Close()
		_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))

		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
		if _, err := clientConn.WriteTo(req.Raw, srv.UDPAddr()); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 576)
		n, _, err := clientConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom binding response: %v", err)
		}
		var resp stun.Message
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatalf("Decode response: %v", err)
		}
		if resp.Type != stun.BindingSuccess {
			t.Fatalf("got %v, want BindingSuccess", resp.Type)
		}

		// Oversized and malformed packets increment counters.
		_, _ = clientConn.WriteTo(bytes.Repeat([]byte{0x42}, 900), srv.UDPAddr())
		_, _ = clientConn.WriteTo([]byte("not-a-stun-packet"), srv.UDPAddr())
		time.Sleep(30 * time.Millisecond)

		st := srv.Stats()
		if st.BindingResponses != 1 || st.OversizedPackets != 1 || st.MalformedPackets != 1 {
			t.Fatalf("unexpected insecure STUN stats: %+v", st)
		}
	})
}
