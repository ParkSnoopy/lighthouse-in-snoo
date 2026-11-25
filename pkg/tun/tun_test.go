package tun_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/tun"
)

func buildIPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	s4 := src.As4()
	d4 := dst.As4()
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], payload)
	return pkt
}

func TestParsePacketEndpoints(t *testing.T) {
	t.Parallel()

	src := netip.MustParseAddr("100.64.1.2")
	dst := netip.MustParseAddr("100.64.3.4")
	v4 := buildIPv4Packet(src, dst, []byte("hello"))
	gotSrc, gotDst, ok := tun.ParsePacketEndpoints(v4)
	if !ok || gotSrc != src || gotDst != dst {
		t.Fatalf("ParsePacketEndpoints(IPv4) = (%v, %v, %v)", gotSrc, gotDst, ok)
	}

	v6 := make([]byte, 44)
	v6[0] = 0x60
	s6 := netip.MustParseAddr("fd00::1").As16()
	d6 := netip.MustParseAddr("fd00::2").As16()
	copy(v6[8:24], s6[:])
	copy(v6[24:40], d6[:])
	gotSrc6, gotDst6, ok6 := tun.ParsePacketEndpoints(v6)
	if !ok6 || gotSrc6.String() != "fd00::1" || gotDst6.String() != "fd00::2" {
		t.Fatalf("ParsePacketEndpoints(IPv6) = (%v, %v, %v)", gotSrc6, gotDst6, ok6)
	}

	if _, _, ok := tun.ParsePacketEndpoints([]byte{0x45, 0x00}); ok {
		t.Fatal("expected truncated IPv4 packet to be rejected")
	}
	if _, _, ok := tun.ParsePacketEndpoints([]byte{0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("expected unknown IP version to be rejected")
	}
}

func makeHubTLS(t *testing.T) (srvTLS, cliTLS *tls.Config) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}},
		&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
}

func TestRouterBidirectionalIPForwardingAndAntiSpoofing(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS := makeHubTLS(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "wss://" + ln.Addr().String()
	srv, err := hub.New(&hub.Config{
		HTTPSListener:   ln,
		TLSConfig:       srvTLS,
		HubOrigin:       origin,
		EnableSTUN:      true,
		STUNSListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()
	allowAll := peer.ConsentFunc(func(_ context.Context, _ *peer.IncomingRequest) peer.ConsentDecision {
		return peer.ConsentAllow
	})

	sessBCh := make(chan *peer.Session, 1)
	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:             kpA,
		SignalingURL:        origin + "/v1/signal",
		TLSConfig:           cliTLS,
		STUNServerURI:       "stuns:" + srv.STUNSAddr().String(),
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Consent:             allowAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:             kpB,
		SignalingURL:        origin + "/v1/signal",
		TLSConfig:           cliTLS,
		STUNServerURI:       "stuns:" + srv.STUNSAddr().String(),
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Consent:             allowAll,
		OnSession:           func(s *peer.Session) { sessBCh <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := clientA.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatal(err)
	}

	// Hub auto-ACL requires target B to broadcast on a passphrase channel joined by caller A.
	chID, err := clientB.SetBroadcast(ctx, true, "tun-room", "PeerB")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientA.JoinChannel(ctx, "tun-room"); err != nil {
		t.Fatal(err)
	}
	waitDisc := time.Now().Add(3 * time.Second)
	for time.Now().Before(waitDisc) {
		if len(clientA.DiscoveredPeers(chID)) == 1 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	sessA, err := clientA.Connect(ctx, kpB.PeerID)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sessB := <-sessBCh

	devA := tun.NewMemoryDevice("lhA", tun.DefaultMTU)
	devB := tun.NewMemoryDevice("lhB", tun.DefaultMTU)
	routerA, err := tun.NewRouter(devA, clientA.VirtualIP())
	if err != nil {
		t.Fatal(err)
	}
	defer routerA.Close()
	routerB, err := tun.NewRouter(devB, clientB.VirtualIP())
	if err != nil {
		t.Fatal(err)
	}
	defer routerB.Close()

	if _, err := routerA.AttachSession(sessA); err != nil {
		t.Fatal(err)
	}
	if _, err := routerB.AttachSession(sessB); err != nil {
		t.Fatal(err)
	}

	// Forward valid IPv4 packet A -> B through bound TUN interfaces.
	pktAB := buildIPv4Packet(clientA.VirtualIP(), clientB.VirtualIP(), []byte("tun-a-to-b"))
	if err := devA.InjectOutbound(ctx, pktAB); err != nil {
		t.Fatal(err)
	}
	gotAB, err := devB.ReadInbound(ctx)
	if err != nil {
		t.Fatalf("ReadInbound B: %v", err)
	}
	if !bytes.Equal(gotAB, pktAB) {
		t.Fatalf("B inbound mismatch: got %x want %x", gotAB, pktAB)
	}

	// Reverse direction B -> A.
	pktBA := buildIPv4Packet(clientB.VirtualIP(), clientA.VirtualIP(), []byte("tun-b-to-a"))
	if err := devB.InjectOutbound(ctx, pktBA); err != nil {
		t.Fatal(err)
	}
	gotBA, err := devA.ReadInbound(ctx)
	if err != nil {
		t.Fatalf("ReadInbound A: %v", err)
	}
	if !bytes.Equal(gotBA, pktBA) {
		t.Fatalf("A inbound mismatch")
	}

	// Spoofed local source IP outbound -> dropped locally.
	spoofOut := buildIPv4Packet(netip.MustParseAddr("100.64.0.1"), clientB.VirtualIP(), []byte("spoof"))
	_ = devA.InjectOutbound(ctx, spoofOut)

	// Unrouted destination IP outbound -> dropped locally.
	unrouted := buildIPv4Packet(clientA.VirtualIP(), netip.MustParseAddr("100.127.255.254"), []byte("unrouted"))
	_ = devA.InjectOutbound(ctx, unrouted)

	// Spoofed remote source IP injected directly on the wire -> dropped by Router B anti-spoofing!
	spoofWire := buildIPv4Packet(netip.MustParseAddr("100.64.250.250"), clientB.VirtualIP(), []byte("wire-spoof"))
	if err := sessA.Send(ctx, spoofWire); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stA := routerA.Stats()
		stB := routerB.Stats()
		if stA.DroppedSpoofed >= 1 && stA.DroppedUnrouted >= 1 && stB.DroppedSpoofed >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	stA := routerA.Stats()
	stB := routerB.Stats()
	if stA.DroppedSpoofed < 1 || stA.DroppedUnrouted < 1 {
		t.Fatalf("expected outbound spoofed & unrouted drops on routerA, got %+v", stA)
	}
	if stB.DroppedSpoofed < 1 {
		t.Fatalf("expected inbound wire anti-spoof drop on routerB, got %+v", stB)
	}
	leakCtx, leakCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	leaked, leakErr := devB.ReadInbound(leakCtx)
	leakCancel()
	if leakErr == nil {
		t.Fatalf("spoofed packet leaked to TUN device B: %x", leaked)
	}
}
