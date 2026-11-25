package acceptance_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/v5/vnet"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/internal/stunserver"
	"lighthouse-in-snoo/internal/turnserver"
	"lighthouse-in-snoo/pkg/peer"
)

// TestSTUNSAndTURNSDTLS13UDPAndInsecureOptIn verifies:
//   - Plaintext stun:/turn: are rejected by default on both Hub and Peer without --insecure.
//   - stuns: and turns: prioritize DTLS 1.3 over UDP (:5349/udp) with strict X.509 validation.
//   - DTLS 1.3 / UDP turns: relay connects peers end to end over DTLS 1.3 even when direct UDP is blocked.
//   - Opt-in --insecure (AllowInsecure / AllowInsecureICE) enables plaintext stun: and turn: cleanly.
func TestSTUNSAndTURNSDTLS13UDPAndInsecureOptIn(t *testing.T) {
	t.Parallel()

	t.Run("HubAndPeerRejectInsecureByDefault", func(t *testing.T) {
		t.Parallel()
		ids := newTestMeshIdentities(t)
		pki := generateTestPKI(t)
		rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rawLn.Close()

		// Hub MUST reject plaintext UDP STUNListenAddr without AllowInsecure=true.
		if _, err := hub.New(hub.Config{
			HTTPSListener:  rawLn,
			TLSConfig:      pki.serverTLS,
			HubOrigin:      "wss://" + rawLn.Addr().String(),
			STUNListenAddr: "127.0.0.1:0",
			Policy:         ids.policy,
		}); !errors.Is(err, stunserver.ErrInsecureSTUNProhibited) {
			t.Fatalf("expected ErrInsecureSTUNProhibited from hub.New, got %v", err)
		}

		// Peer MUST reject plaintext stun: and turn: without AllowInsecureICE=true.
		for _, uri := range []string{"stun:127.0.0.1:3478", "turn:127.0.0.1:3478"} {
			if _, err := peer.NewClient(peer.Config{
				KeyPair:        ids.peerA,
				Policy:         ids.policy,
				SignalingURL:   "wss://127.0.0.1:8443/v1/signal",
				STUNServerURI:  uri,
				TURNUsername:   "u",
				TURNCredential: "p",
			}); !errors.Is(err, peer.ErrInsecureICEProhibited) {
				t.Fatalf("expected ErrInsecureICEProhibited for %q, got %v", uri, err)
			}
		}
	})

	t.Run("STUNSDTLS13RejectsUntrustedCA", func(t *testing.T) {
		t.Parallel()
		ids := newTestMeshIdentities(t)
		_, _, _, wsURL, stunsURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

		wrongCA := x509.NewCertPool()
		client, err := peer.NewClient(peer.Config{
			KeyPair:       ids.peerA,
			Membership:    ids.memA,
			Policy:        ids.policy,
			SignalingURL:  wsURL,
			TLSConfig:     &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: wrongCA},
			STUNServerURI: stunsURI,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := client.ProbeSTUNS(ctx); err == nil {
			t.Fatal("expected ProbeSTUNS to fail closed when server certificate is not trusted")
		}
	})

	t.Run("TURNSDTLS13UDPRelayEndToEnd", func(t *testing.T) {
		t.Parallel()
		ids := newTestMeshIdentities(t)
		pki := generateTestPKI(t)

		rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		boundAddr := rawLn.Addr().String()
		wsURL := "wss://" + boundAddr + "/v1/signal"

		const turnSecret = "lighthouse-turns-hmac-secret"
		srv, err := hub.New(hub.Config{
			HTTPSListener:     rawLn,
			TLSConfig:         pki.serverTLS,
			HubOrigin:         "wss://" + boundAddr,
			EnableTURN:        true,
			STUNSListenAddr:   "127.0.0.1:0",
			TURNSecret:        turnSecret,
			TURNRealm:         "lighthouse",
			TURNRelayBindAddr: "127.0.0.1",
			Policy:            ids.policy,
		})
		if err != nil {
			_ = rawLn.Close()
			t.Fatalf("hub.New with DTLS 1.3 TURNS: %v", err)
		}
		defer srv.Close()

		if !srv.TURNActive() || srv.STUNSAddr() == nil {
			t.Fatalf("expected TURNS DTLS 1.3 / UDP listener active, got turn=%v addr=%v", srv.TURNActive(), srv.STUNSAddr())
		}

		// Bare "turns:<ip>:<port>" automatically prioritizes DTLS 1.3 over UDP!
		turnsURI := "turns:" + srv.STUNSAddr().String()
		userA, passA, err := turnserver.GenerateCredentials(turnSecret, ids.peerA.PeerID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		userB, passB, err := turnserver.GenerateCredentials(turnSecret, ids.peerB.PeerID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		sessBCh := make(chan *peer.Session, 1)
		clientA, err := peer.NewClient(peer.Config{
			KeyPair:            ids.peerA,
			Membership:         ids.memA,
			Policy:             ids.policy,
			SignalingURL:       wsURL,
			TLSConfig:          pki.clientTLS,
			TURNServerURI:      turnsURI,
			TURNUsername:       userA,
			TURNCredential:     passA,
			ICETransportPolicy: webrtc.ICETransportPolicyRelay,
			NetworkTypes:       []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:    true,
		})
		if err != nil {
			t.Fatalf("NewClient A (turns): %v", err)
		}
		defer clientA.Close()

		clientB, err := peer.NewClient(peer.Config{
			KeyPair:            ids.peerB,
			Membership:         ids.memB,
			Policy:             ids.policy,
			SignalingURL:       wsURL,
			TLSConfig:          pki.clientTLS,
			TURNServerURI:      turnsURI,
			TURNUsername:       userB,
			TURNCredential:     passB,
			ICETransportPolicy: webrtc.ICETransportPolicyRelay,
			NetworkTypes:       []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:    true,
			OnSession:          func(s *peer.Session) { sessBCh <- s },
		})
		if err != nil {
			t.Fatalf("NewClient B (turns): %v", err)
		}
		defer clientB.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := clientA.Register(ctx); err != nil {
			t.Fatalf("Register A: %v", err)
		}
		if err := clientB.Register(ctx); err != nil {
			t.Fatalf("Register B: %v", err)
		}
		if _, err := clientA.ProbeSTUNS(ctx); err != nil {
			t.Fatalf("ProbeSTUNS on TURNS DTLS 1.3 / UDP port failed: %v", err)
		}

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatalf("Connect over DTLS 1.3 TURNS relay failed: %v", err)
		}
		var sessB *peer.Session
		select {
		case sessB = <-sessBCh:
		case <-ctx.Done():
			t.Fatal("timeout waiting for responder session B over TURNS")
		}

		diagA := sessA.Diagnostics()
		if diagA.LocalCandidateType != "relay" || diagA.RemoteCandidateType != "relay" {
			t.Fatalf("expected relay-relay pair via DTLS 1.3 TURNS, got (%s, %s)", diagA.LocalCandidateType, diagA.RemoteCandidateType)
		}
		if diagA.DTLSVersion != peer.ExpectedDTLS13HexVersion {
			t.Fatalf("expected end-to-end DTLS 1.3 (FEFC) over TURNS relay, got %q", diagA.DTLSVersion)
		}

		msgAB := []byte("turns-dtls13-udp-A-to-B")
		msgBA := []byte("turns-dtls13-udp-B-to-A")
		if err := sessA.Send(ctx, msgAB); err != nil {
			t.Fatal(err)
		}
		if got := <-sessB.Messages(); !bytes.Equal(got, msgAB) {
			t.Fatalf("A->B mismatch: %q", string(got))
		}
		if err := sessB.Send(ctx, msgBA); err != nil {
			t.Fatal(err)
		}
		if got := <-sessA.Messages(); !bytes.Equal(got, msgBA) {
			t.Fatalf("B->A mismatch: %q", string(got))
		}
		t.Logf("Verified DTLS 1.3 / UDP TURNS Relay: Pair=%s DTLS=%s", diagA.SelectedPair, diagA.DTLSVersion)
	})

	t.Run("TURNSDTLS13UDPBypassesRestrictiveSymmetricNATs", func(t *testing.T) {
		t.Parallel()
		lf := quietPionLogger()
		wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

		turnNet := newVNetNIC(t, "203.0.113.10")
		_ = wan.AddNet(turnNet)

		// Completely block direct UDP between NAT A (203.0.113.51) and NAT B (203.0.113.52).
		wan.AddChunkFilter(func(c vnet.Chunk) bool {
			src := c.SourceAddr().(*net.UDPAddr).IP.String()
			dst := c.DestinationAddr().(*net.UDPAddr).IP.String()
			if (src == "203.0.113.51" && dst == "203.0.113.52") || (src == "203.0.113.52" && dst == "203.0.113.51") {
				return false
			}
			return true
		})

		natA := newVNetRouter(t, &vnet.RouterConfig{
			CIDR:      "192.168.51.0/24",
			StaticIPs: []string{"203.0.113.51"},
			NATType: &vnet.NATType{
				MappingBehavior:   vnet.EndpointAddrPortDependent,
				FilteringBehavior: vnet.EndpointAddrPortDependent,
			},
			LoggerFactory: lf,
		})
		netA := newVNetNIC(t, "192.168.51.2")
		_ = natA.AddNet(netA)
		_ = wan.AddRouter(natA)

		natB := newVNetRouter(t, &vnet.RouterConfig{
			CIDR:      "192.168.52.0/24",
			StaticIPs: []string{"203.0.113.52"},
			NATType: &vnet.NATType{
				MappingBehavior:   vnet.EndpointAddrPortDependent,
				FilteringBehavior: vnet.EndpointAddrPortDependent,
			},
			LoggerFactory: lf,
		})
		netB := newVNetNIC(t, "192.168.52.2")
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

		srv, err := hub.New(hub.Config{
			HTTPSListener:     rawLn,
			TLSConfig:         pki.serverTLS,
			HubOrigin:         "wss://" + boundAddr,
			EnableTURN:        true,
			STUNSPacketConn:   turnConn,
			TURNUsers:         map[string]string{"peer-a": "secret-a", "peer-b": "secret-b"},
			TURNPublicIP:      net.ParseIP("203.0.113.10"),
			TURNRelayBindAddr: "203.0.113.10",
			TURNNet:           turnNet,
			PionLoggerFactory: lf,
			Policy:            ids.policy,
		})
		if err != nil {
			_ = rawLn.Close()
			t.Fatalf("hub.New vnet TURNS: %v", err)
		}
		defer srv.Close()

		sessBCh := make(chan *peer.Session, 1)
		clientA, err := peer.NewClient(peer.Config{
			KeyPair:           ids.peerA,
			Membership:        ids.memA,
			Policy:            ids.policy,
			SignalingURL:      wsURL,
			TLSConfig:         pki.clientTLS,
			TURNServerURI:     "turns:203.0.113.10:5349",
			TURNUsername:      "peer-a",
			TURNCredential:    "secret-a",
			NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:   false,
			VNet:              netA,
			PionLoggerFactory: lf,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clientA.Close()

		clientB, err := peer.NewClient(peer.Config{
			KeyPair:           ids.peerB,
			Membership:        ids.memB,
			Policy:            ids.policy,
			SignalingURL:      wsURL,
			TLSConfig:         pki.clientTLS,
			TURNServerURI:     "turns:203.0.113.10:5349",
			TURNUsername:      "peer-b",
			TURNCredential:    "secret-b",
			NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:   false,
			VNet:              netB,
			PionLoggerFactory: lf,
			OnSession:         func(s *peer.Session) { sessBCh <- s },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clientB.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = clientA.Register(ctx)
		_ = clientB.Register(ctx)

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatalf("Connect across symmetric NATs via DTLS 1.3 TURNS failed: %v", err)
		}
		sessB := <-sessBCh

		diag := sessA.Diagnostics()
		if diag.DTLSVersion != peer.ExpectedDTLS13HexVersion {
			t.Fatalf("expected DTLS 1.3, got %q", diag.DTLSVersion)
		}
		if diag.LocalCandidateType != "relay" && diag.RemoteCandidateType != "relay" {
			t.Fatalf("expected relay path when direct UDP is blocked, got (%s, %s)", diag.LocalCandidateType, diag.RemoteCandidateType)
		}
		if err := sessA.Send(ctx, []byte("symmetric-nat-turns-ok")); err != nil {
			t.Fatal(err)
		}
		if got := <-sessB.Messages(); string(got) != "symmetric-nat-turns-ok" {
			t.Fatalf("unexpected payload %q", string(got))
		}
	})

	t.Run("InsecureOptInAllowsPlaintextSTUNAndTURN", func(t *testing.T) {
		t.Parallel()
		ids := newTestMeshIdentities(t)
		pki := generateTestPKI(t)

		rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		boundAddr := rawLn.Addr().String()
		wsURL := "wss://" + boundAddr + "/v1/signal"

		srv, err := hub.New(hub.Config{
			HTTPSListener:     rawLn,
			TLSConfig:         pki.serverTLS,
			HubOrigin:         "wss://" + boundAddr,
			AllowInsecure:     true,
			EnableTURN:        true,
			STUNListenAddr:    "127.0.0.1:0",
			TURNUsers:         map[string]string{"u1": "p1"},
			TURNRelayBindAddr: "127.0.0.1",
			Policy:            ids.policy,
		})
		if err != nil {
			_ = rawLn.Close()
			t.Fatalf("hub.New AllowInsecure: %v", err)
		}
		defer srv.Close()

		turnURI := "turn:" + srv.STUNUDPAddr().String()
		sessBCh := make(chan *peer.Session, 1)
		clientA, err := peer.NewClient(peer.Config{
			KeyPair:            ids.peerA,
			Membership:         ids.memA,
			Policy:             ids.policy,
			SignalingURL:       wsURL,
			TLSConfig:          pki.clientTLS,
			TURNServerURI:      turnURI,
			TURNUsername:       "u1",
			TURNCredential:     "p1",
			AllowInsecureICE:   true,
			ICETransportPolicy: webrtc.ICETransportPolicyRelay,
			NetworkTypes:       []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:    true,
		})
		if err != nil {
			t.Fatalf("NewClient A insecure turn: %v", err)
		}
		defer clientA.Close()

		clientB, err := peer.NewClient(peer.Config{
			KeyPair:            ids.peerB,
			Membership:         ids.memB,
			Policy:             ids.policy,
			SignalingURL:       wsURL,
			TLSConfig:          pki.clientTLS,
			TURNServerURI:      turnURI,
			TURNUsername:       "u1",
			TURNCredential:     "p1",
			AllowInsecureICE:   true,
			ICETransportPolicy: webrtc.ICETransportPolicyRelay,
			NetworkTypes:       []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:    true,
			OnSession:          func(s *peer.Session) { sessBCh <- s },
		})
		if err != nil {
			t.Fatalf("NewClient B insecure turn: %v", err)
		}
		defer clientB.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = clientA.Register(ctx)
		_ = clientB.Register(ctx)

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatalf("Connect with opt-in --insecure plaintext turn: failed: %v", err)
		}
		sessB := <-sessBCh

		if err := sessA.Send(ctx, []byte("insecure-opt-in-turn-ok")); err != nil {
			t.Fatal(err)
		}
		if got := <-sessB.Messages(); string(got) != "insecure-opt-in-turn-ok" {
			t.Fatalf("unexpected payload %q", string(got))
		}
	})
}
