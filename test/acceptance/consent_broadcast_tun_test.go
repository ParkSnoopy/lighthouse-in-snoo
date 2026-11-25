package acceptance_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v5/vnet"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/tun"
)

func buildTestIPv4Packet(src, dst netip.Addr, body []byte) []byte {
	s4 := src.As4()
	d4 := dst.As4()
	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], body)
	return pkt
}

// TestPassphraseBroadcastIsolationAndUserConsent verifies v0.2.0 security invariants:
//   - Broadcasts are strictly scoped by offline passphrase (zero leakage to other passphrases).
//   - Incoming connections require explicit user consent (Allow / Deny / Blacklist).
//   - Allowed tunnels route IPv4 packets across bound TUN devices.
//   - Blacklisting terminates active tunnels, hides broadcasts, and blocks future offers.
func TestPassphraseBroadcastIsolationAndUserConsent(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, stunsURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	var nextDecision atomic.Int32
	nextDecision.Store(int32(peer.ConsentDeny))

	sessBCh := make(chan *peer.Session, 2)
	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:             ids.peerA,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		STUNServerURI:       stunsURI,
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Consent:             allowAllConsent(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:             ids.peerB,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		STUNServerURI:       stunsURI,
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Consent: peer.ConsentFunc(func(_ context.Context, req *peer.IncomingRequest) peer.ConsentDecision {
			if req.PeerID != ids.peerA.PeerID {
				return peer.ConsentDeny
			}
			return peer.ConsentDecision(nextDecision.Load())
		}),
		OnSession: func(s *peer.Session) { sessBCh <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	clientC, err := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerC,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunsURI,
		IncludeLoopback: true,
		Consent:         denyAllConsent(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientC.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := clientA.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientC.Register(ctx); err != nil {
		t.Fatal(err)
	}

	// Peer A broadcasts under passphrase "project-apollo"; B joins "project-apollo"; C joins "project-gemini".
	chApollo, err := clientA.SetBroadcast(ctx, true, "project-apollo", "Apollo-Node")
	if err != nil {
		t.Fatalf("A SetBroadcast: %v", err)
	}
	if _, err := clientB.JoinChannel(ctx, "project-apollo"); err != nil {
		t.Fatalf("B JoinChannel: %v", err)
	}
	chGemini, err := clientC.JoinChannel(ctx, "project-gemini")
	if err != nil {
		t.Fatalf("C JoinChannel: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(clientB.DiscoveredPeers(chApollo)) == 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	gotB := clientB.DiscoveredPeers(chApollo)
	if len(gotB) != 1 || gotB[0].PeerID != ids.peerA.PeerID || gotB[0].DisplayName != "Apollo-Node" {
		t.Fatalf("expected Peer B to discover Apollo-Node, got %+v", gotB)
	}
	if gotC := clientC.DiscoveredPeers(chGemini); len(gotC) != 0 {
		t.Fatalf("blast radius violation: Peer C on different passphrase saw %+v", gotC)
	}

	// 1. User B denies incoming offer from Peer A.
	if _, err := clientA.Connect(ctx, ids.peerB.PeerID); !errors.Is(err, peer.ErrUserDenied) {
		t.Fatalf("expected ErrUserDenied, got %v", err)
	}

	// 2. User B allows incoming offer from Peer A -> TUN routing succeeds.
	nextDecision.Store(int32(peer.ConsentAllow))
	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("Connect after Allow: %v", err)
	}
	sessB := <-sessBCh

	devA := tun.NewMemoryDevice("lhA", tun.DefaultMTU)
	devB := tun.NewMemoryDevice("lhB", tun.DefaultMTU)
	rA, err := tun.NewRouter(devA, clientA.VirtualIP())
	if err != nil {
		t.Fatal(err)
	}
	defer rA.Close()
	rB, err := tun.NewRouter(devB, clientB.VirtualIP())
	if err != nil {
		t.Fatal(err)
	}
	defer rB.Close()
	if _, err := rA.AttachSession(sessA); err != nil {
		t.Fatal(err)
	}
	if _, err := rB.AttachSession(sessB); err != nil {
		t.Fatal(err)
	}

	pkt := buildTestIPv4Packet(clientA.VirtualIP(), clientB.VirtualIP(), []byte("consent-allowed-tun"))
	if err := devA.InjectOutbound(ctx, pkt); err != nil {
		t.Fatal(err)
	}
	got, err := devB.ReadInbound(ctx)
	if err != nil {
		t.Fatalf("ReadInbound B: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("TUN payload mismatch")
	}

	// 3. User B blacklists Peer A -> active session drops, broadcasts hidden, future offers rejected.
	if err := clientB.Blacklist(ids.peerA.PeerID); err != nil {
		t.Fatal(err)
	}
	if len(clientB.DiscoveredPeers(chApollo)) != 0 {
		t.Fatalf("expected blacklisted Peer A hidden from DiscoveredPeers")
	}
	select {
	case <-sessA.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("expected active session on A to close after B blacklisted A")
	}
	if _, err := clientA.Connect(ctx, ids.peerB.PeerID); !errors.Is(err, peer.ErrPeerBlacklisted) {
		t.Fatalf("expected ErrPeerBlacklisted after blacklisting, got %v", err)
	}
}

// TestUniversalPublicRelayAutoProvisionedAcrossSymmetricNATs verifies that a zero-config hub
// with EnableTURN=true automatically provisions ephemeral DTLS 1.3/UDP TURNS credentials to
// registered peers and bridges restrictive symmetric NATs without any static TURN config.
func TestUniversalPublicRelayAutoProvisionedAcrossSymmetricNATs(t *testing.T) {
	t.Parallel()

	lf := quietPionLogger()
	wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

	turnNet := newVNetNIC(t, "203.0.113.10")
	_ = wan.AddNet(turnNet)

	// Block all direct UDP between NAT A and NAT B so universal relay is mandatory.
	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		src := c.SourceAddr().(*net.UDPAddr).IP.String()
		dst := c.DestinationAddr().(*net.UDPAddr).IP.String()
		if (src == "203.0.113.61" && dst == "203.0.113.62") || (src == "203.0.113.62" && dst == "203.0.113.61") {
			return false
		}
		return true
	})

	natA := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:      "192.168.61.0/24",
		StaticIPs: []string{"203.0.113.61"},
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointAddrPortDependent,
			FilteringBehavior: vnet.EndpointAddrPortDependent,
		},
		LoggerFactory: lf,
	})
	netA := newVNetNIC(t, "192.168.61.2")
	_ = natA.AddNet(netA)
	_ = wan.AddRouter(natA)

	natB := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:      "192.168.62.0/24",
		StaticIPs: []string{"203.0.113.62"},
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointAddrPortDependent,
			FilteringBehavior: vnet.EndpointAddrPortDependent,
		},
		LoggerFactory: lf,
	})
	netB := newVNetNIC(t, "192.168.62.2")
	_ = natB.AddNet(netB)
	_ = wan.AddRouter(natB)

	_ = wan.Start()
	defer wan.Stop()

	turnConn, err := turnNet.ListenPacket("udp4", "203.0.113.10:5349")
	if err != nil {
		t.Fatal(err)
	}
	defer turnConn.Close()

	ids := newTestMeshIdentities(t)
	pki := generateTestPKI(t, net.ParseIP("203.0.113.10"))
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	boundAddr := rawLn.Addr().String()
	wsURL := "wss://" + boundAddr + "/v1/signal"

	// Zero-config universal hub: NO TURNSecret, NO TURNUsers, NO Policy.
	srv, err := hub.New(&hub.Config{
		HTTPSListener:     rawLn,
		TLSConfig:         pki.serverTLS,
		HubOrigin:         "wss://" + boundAddr,
		EnableTURN:        true,
		STUNSPacketConn:   turnConn,
		TURNPublicIP:      net.ParseIP("203.0.113.10"),
		TURNAdvertiseHost: "203.0.113.10",
		TURNRelayBindAddr: "203.0.113.10",
		TURNNet:           turnNet,
		PionLoggerFactory: lf,
	})
	if err != nil {
		_ = rawLn.Close()
		t.Fatalf("hub.New universal relay: %v", err)
	}
	defer srv.Close()

	// Peers pass NO manual STUN/TURN URI or credentials; UseHubRelay auto-adopts hub relay!
	sessBCh := make(chan *peer.Session, 1)
	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:           ids.peerA,
		SignalingURL:      wsURL,
		TLSConfig:         pki.clientTLS,
		NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:   false,
		VNet:              netA,
		PionLoggerFactory: lf,
		Consent:           allowAllConsent(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:           ids.peerB,
		SignalingURL:      wsURL,
		TLSConfig:         pki.clientTLS,
		NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:   false,
		VNet:              netB,
		PionLoggerFactory: lf,
		Consent:           allowAllConsent(),
		OnSession:         func(s *peer.Session) { sessBCh <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := clientA.Register(ctx); err != nil {
		t.Fatalf("Register A: %v", err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatalf("Register B: %v", err)
	}

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("Connect via auto-provisioned universal relay failed: %v", err)
	}
	sessB := <-sessBCh

	diag := sessA.Diagnostics()
	if diag.DTLSVersion != peer.ExpectedDTLS13HexVersion {
		t.Fatalf("expected DTLS 1.3, got %q", diag.DTLSVersion)
	}
	if diag.LocalCandidateType != "relay" && diag.RemoteCandidateType != "relay" {
		t.Fatalf("expected relay path via universal hub relay, got (%s, %s)", diag.LocalCandidateType, diag.RemoteCandidateType)
	}

	devA := tun.NewMemoryDevice("lhA", tun.DefaultMTU)
	devB := tun.NewMemoryDevice("lhB", tun.DefaultMTU)
	rA, _ := tun.NewRouter(devA, clientA.VirtualIP())
	defer rA.Close()
	rB, _ := tun.NewRouter(devB, clientB.VirtualIP())
	defer rB.Close()
	_, _ = rA.AttachSession(sessA)
	_, _ = rB.AttachSession(sessB)

	pkt := buildTestIPv4Packet(clientA.VirtualIP(), clientB.VirtualIP(), []byte("universal-relay-tun-ok"))
	if err := devA.InjectOutbound(ctx, pkt); err != nil {
		t.Fatal(err)
	}
	got, err := devB.ReadInbound(ctx)
	if err != nil {
		t.Fatalf("ReadInbound B universal relay: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("TUN packet mismatch across universal relay")
	}
	t.Logf("Universal Public Relay Verified: Pair=%s DTLS=%s", diag.SelectedPair, diag.DTLSVersion)
}

// TestHubOfflinePassphraseGate verifies that a hub configured with an offline shared
// passphrase rejects missing/wrong passphrases and admits matching peers via HMAC proof.
func TestHubOfflinePassphraseGate(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	pki := generateTestPKI(t)
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	boundAddr := rawLn.Addr().String()
	wsURL := "wss://" + boundAddr + "/v1/signal"

	srv, err := hub.New(&hub.Config{
		HTTPSListener:   rawLn,
		TLSConfig:       pki.serverTLS,
		HubOrigin:       "wss://" + boundAddr,
		Passphrase:      "offline-vault-key",
		EnableSTUN:      true,
		STUNSListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		_ = rawLn.Close()
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Missing passphrase rejected.
	noPass, _ := peer.NewClient(&peer.Config{
		KeyPair:      ids.peerA,
		SignalingURL: wsURL,
		TLSConfig:    pki.clientTLS,
	})
	defer noPass.Close()
	if err := noPass.Register(ctx); err == nil {
		t.Fatal("expected registration without hub passphrase to fail")
	}

	// Wrong passphrase rejected.
	wrongPass, _ := peer.NewClient(&peer.Config{
		KeyPair:       ids.peerA,
		SignalingURL:  wsURL,
		HubPassphrase: "wrong-key",
		TLSConfig:     pki.clientTLS,
	})
	defer wrongPass.Close()
	if err := wrongPass.Register(ctx); err == nil {
		t.Fatal("expected registration with wrong hub passphrase to fail")
	}

	// Matching passphrase admitted.
	rightPass, _ := peer.NewClient(&peer.Config{
		KeyPair:       ids.peerA,
		SignalingURL:  wsURL,
		HubPassphrase: "offline-vault-key",
		TLSConfig:     pki.clientTLS,
	})
	defer rightPass.Close()
	if err := rightPass.Register(ctx); err != nil {
		t.Fatalf("expected matching hub passphrase to register: %v", err)
	}
}
