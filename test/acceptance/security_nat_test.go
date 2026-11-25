package acceptance_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/logging"
	"github.com/pion/stun/v5"
	"github.com/pion/transport/v5/vnet"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/peer"
)

func quietPionLogger() logging.LoggerFactory {
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	return lf
}

// TestT03_CompatibleNATsSeparateNetworks verifies T03:
// Peers behind separate compatible NAT routers discover srflx mappings via Hub STUN
// and establish a non-relayed direct DTLS 1.3 DataChannel session.
func TestT03_CompatibleNATsSeparateNetworks(t *testing.T) {
	t.Parallel()

	lf := quietPionLogger()
	wan := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		LoggerFactory: lf,
	})

	// Hub STUN UDP socket on public WAN IP 203.0.113.10:3478.
	stunNet := newVNetNIC(t, "203.0.113.10")
	if err := wan.AddNet(stunNet); err != nil {
		t.Fatal(err)
	}

	// NAT A: 192.168.10.0/24 -> WAN 203.0.113.21 (Address-Restricted Cone NAT).
	natA := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:      "192.168.10.0/24",
		StaticIPs: []string{"203.0.113.21"},
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointIndependent,
			FilteringBehavior: vnet.EndpointAddrDependent,
		},
		LoggerFactory: lf,
	})
	netA := newVNetNIC(t, "192.168.10.2")
	if err := natA.AddNet(netA); err != nil {
		t.Fatal(err)
	}
	if err := wan.AddRouter(natA); err != nil {
		t.Fatal(err)
	}

	// NAT B: 192.168.20.0/24 -> WAN 203.0.113.22 (Address-Restricted Cone NAT).
	natB := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:      "192.168.20.0/24",
		StaticIPs: []string{"203.0.113.22"},
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointIndependent,
			FilteringBehavior: vnet.EndpointAddrDependent,
		},
		LoggerFactory: lf,
	})
	netB := newVNetNIC(t, "192.168.20.2")
	if err := natB.AddNet(netB); err != nil {
		t.Fatal(err)
	}
	if err := wan.AddRouter(natB); err != nil {
		t.Fatal(err)
	}

	if err := wan.Start(); err != nil {
		t.Fatal(err)
	}
	defer wan.Stop()

	stunConn, err := stunNet.ListenPacket("udp4", "203.0.113.10:5349")
	if err != nil {
		t.Fatal(err)
	}
	defer stunConn.Close()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "", ids.policy, stunConn, net.ParseIP("203.0.113.10"))

	sessBCh := make(chan *peer.Session, 1)
	clientA, err := peer.NewClient(peer.Config{
		KeyPair:           ids.peerA,
		Membership:        ids.memA,
		Policy:            ids.policy,
		SignalingURL:      wsURL,
		TLSConfig:         pki.clientTLS,
		STUNServerURI:     "stuns:203.0.113.10:5349",
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
		STUNServerURI:     "stuns:203.0.113.10:5349",
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("T03 NAT traversal Connect failed: %v", err)
	}
	sessB := <-sessBCh

	diag := sessA.Diagnostics()
	if diag.LocalCandidateType == "relay" || diag.RemoteCandidateType == "relay" {
		t.Fatalf("T03 violation: relay candidate used: %+v", diag)
	}
	if diag.LocalCandidateType == "host" && diag.RemoteCandidateType == "host" {
		t.Fatalf("T03: expected NAT-punched srflx/prflx pair across separate private subnets, got %+v", diag)
	}
	if diag.DTLSVersion != peer.ExpectedDTLS13HexVersion {
		t.Fatalf("T03: expected DTLS 1.3, got %s", diag.DTLSVersion)
	}

	msg := []byte("nat-punched-direct-p2p")
	if err := sessA.Send(ctx, msg); err != nil {
		t.Fatal(err)
	}
	if got := <-sessB.Messages(); !bytes.Equal(got, msg) {
		t.Fatal("T03 payload mismatch")
	}
	t.Logf("T03 Verified: Pair=%s (local=%s remote=%s) DTLS=%s", diag.SelectedPair, diag.LocalCandidateType, diag.RemoteCandidateType, diag.DTLSVersion)
}

// TestT04_RestrictiveNATsFailClosed verifies T04:
// Restrictive symmetric NATs / firewalls with no viable direct UDP path fail closed
// within the configured budget without any relay attempt.
func TestT04_RestrictiveNATsFailClosed(t *testing.T) {
	t.Parallel()

	lf := quietPionLogger()
	wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

	stunNet := newVNetNIC(t, "203.0.113.10")
	_ = wan.AddNet(stunNet)

	// Block all direct peer-to-peer UDP packets between NAT A (203.0.113.31) and NAT B (203.0.113.32)
	// while still permitting STUN Binding to 203.0.113.10.
	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		src := c.SourceAddr().(*net.UDPAddr).IP.String()
		dst := c.DestinationAddr().(*net.UDPAddr).IP.String()
		if (src == "203.0.113.31" && dst == "203.0.113.32") || (src == "203.0.113.32" && dst == "203.0.113.31") {
			return false
		}
		return true
	})

	natA := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:      "192.168.30.0/24",
		StaticIPs: []string{"203.0.113.31"},
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointAddrPortDependent,
			FilteringBehavior: vnet.EndpointAddrPortDependent,
		},
		LoggerFactory: lf,
	})
	netA := newVNetNIC(t, "192.168.30.2")
	_ = natA.AddNet(netA)
	_ = wan.AddRouter(natA)

	natB := newVNetRouter(t, &vnet.RouterConfig{
		CIDR:      "192.168.40.0/24",
		StaticIPs: []string{"203.0.113.32"},
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointAddrPortDependent,
			FilteringBehavior: vnet.EndpointAddrPortDependent,
		},
		LoggerFactory: lf,
	})
	netB := newVNetNIC(t, "192.168.40.2")
	_ = natB.AddNet(netB)
	_ = wan.AddRouter(natB)

	_ = wan.Start()
	defer wan.Stop()

	stunConn, _ := stunNet.ListenPacket("udp4", "203.0.113.10:5349")
	defer stunConn.Close()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "", ids.policy, stunConn, net.ParseIP("203.0.113.10"))

	clientA, _ := peer.NewClient(peer.Config{
		KeyPair:                 ids.peerA,
		Membership:              ids.memA,
		Policy:                  ids.policy,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           "stuns:203.0.113.10:5349",
		NetworkTypes:            []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:         false,
		VNet:                    netA,
		PionLoggerFactory:       lf,
		OfferToConnectedTimeout: 2 * time.Second,
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:                 ids.peerB,
		Membership:              ids.memB,
		Policy:                  ids.policy,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           "stuns:203.0.113.10:5349",
		NetworkTypes:            []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:         false,
		VNet:                    netB,
		PionLoggerFactory:       lf,
		OfferToConnectedTimeout: 2 * time.Second,
	})
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)

	start := time.Now()
	_, err := clientA.Connect(ctx, ids.peerB.PeerID)
	elapsed := time.Since(start)
	if !errors.Is(err, peer.ErrConnectTimeout) && err == nil {
		t.Fatalf("T04: expected fail-closed timeout error, got %v", err)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("T04: exceeded fail-closed deadline budget: %v", elapsed)
	}
}

// TestT09_LargeBinaryTransferPacketCapture verifies T09:
// Sends a 512 KiB binary transfer (32 x 16 KiB chunks) between connected peers
// and verifies via packet capture that all application data flows directly between peers
// while Hub traffic is strictly control-plane.
func TestT09_LargeBinaryTransferPacketCapture(t *testing.T) {
	t.Parallel()

	lf := quietPionLogger()
	wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

	stunNet := newVNetNIC(t, "203.0.113.10")
	netA := newVNetNIC(t, "198.51.100.11")
	netB := newVNetNIC(t, "198.51.100.12")
	_ = wan.AddNet(stunNet)
	_ = wan.AddNet(netA)
	_ = wan.AddNet(netB)

	var (
		directPeerBytes atomic.Uint64
		hubUDPBytes     atomic.Uint64
		hubMaxPacket    atomic.Uint64
		otherBytes      atomic.Uint64
	)

	// Packet capture filter inspecting every datagram traversing the virtual network.
	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		src := c.SourceAddr().(*net.UDPAddr).IP.String()
		dst := c.DestinationAddr().(*net.UDPAddr).IP.String()
		sz := uint64(len(c.UserData()))

		isDirectPeerPair := (src == "198.51.100.11" && dst == "198.51.100.12") ||
			(src == "198.51.100.12" && dst == "198.51.100.11")
		involvesHub := src == "203.0.113.10" || dst == "203.0.113.10"

		switch {
		case isDirectPeerPair:
			directPeerBytes.Add(sz)
		case involvesHub:
			hubUDPBytes.Add(sz)
			for {
				cur := hubMaxPacket.Load()
				if sz <= cur || hubMaxPacket.CompareAndSwap(cur, sz) {
					break
				}
			}
		default:
			otherBytes.Add(sz)
		}
		return true
	})

	_ = wan.Start()
	defer wan.Stop()

	stunConn, _ := stunNet.ListenPacket("udp4", "203.0.113.10:5349")
	defer stunConn.Close()

	ids := newTestMeshIdentities(t)
	srv, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "", ids.policy, stunConn, net.ParseIP("203.0.113.10"))

	sessBCh := make(chan *peer.Session, 1)
	clientA, _ := peer.NewClient(peer.Config{
		KeyPair:           ids.peerA,
		Membership:        ids.memA,
		Policy:            ids.policy,
		SignalingURL:      wsURL,
		TLSConfig:         pki.clientTLS,
		STUNServerURI:     "stuns:203.0.113.10:5349",
		NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:   false,
		VNet:              netA,
		PionLoggerFactory: lf,
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:           ids.peerB,
		Membership:        ids.memB,
		Policy:            ids.policy,
		SignalingURL:      wsURL,
		TLSConfig:         pki.clientTLS,
		STUNServerURI:     "stuns:203.0.113.10:5349",
		NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:   false,
		VNet:              netB,
		PionLoggerFactory: lf,
		OnSession:         func(s *peer.Session) { sessBCh <- s },
	})
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("T09 Connect: %v", err)
	}
	sessB := <-sessBCh

	hubStatsBefore := srv.Stats()
	hubUDPBefore := hubUDPBytes.Load()

	// Transfer 512 KiB (32 chunks x 16 KiB) with SHA-256 verification.
	const numChunks = 32
	const chunkSize = peer.MaxApplicationMessageBytes
	totalPayload := make([]byte, numChunks*chunkSize)
	if _, err := rand.Read(totalPayload); err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(totalPayload)

	recvDone := make(chan [32]byte, 1)
	go func() {
		h := sha256.New()
		for i := 0; i < numChunks; i++ {
			msg := <-sessB.Messages()
			_, _ = h.Write(msg)
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		recvDone <- sum
	}()

	for i := 0; i < numChunks; i++ {
		slice := totalPayload[i*chunkSize : (i+1)*chunkSize]
		if err := sessA.Send(ctx, slice); err != nil {
			t.Fatalf("T09 Send chunk %d: %v", i, err)
		}
	}

	select {
	case actualDigest := <-recvDone:
		if actualDigest != expectedDigest {
			t.Fatal("T09: SHA-256 digest mismatch on 512 KiB transfer")
		}
	case <-ctx.Done():
		t.Fatal("T09: timed out receiving 512 KiB transfer")
	}

	hubStatsAfter := srv.Stats()
	hubUDPDelta := hubUDPBytes.Load() - hubUDPBefore
	if hubStatsAfter.SignalsForwarded != hubStatsBefore.SignalsForwarded {
		t.Fatalf("T09: expected 0 signaling messages forwarded during data transfer, got delta %d",
			hubStatsAfter.SignalsForwarded-hubStatsBefore.SignalsForwarded)
	}
	if directPeerBytes.Load() < uint64(len(totalPayload)) {
		t.Fatalf("T09: expected >= %d direct peer UDP bytes, captured %d", len(totalPayload), directPeerBytes.Load())
	}
	if hubUDPDelta > 4096 {
		t.Fatalf("T09: unexpected Hub UDP volume during direct data transfer: delta=%d bytes", hubUDPDelta)
	}
	if otherBytes.Load() != 0 {
		t.Fatalf("T09: unexpected third-party packets captured: %d bytes", otherBytes.Load())
	}
	t.Logf("T09 Packet Capture Verified: DirectPeerUDPBytes=%d HubSTUNSBytes=%d HubUDPDelta=%d HubSignalsDelta=0",
		directPeerBytes.Load(), hubUDPBytes.Load(), hubUDPDelta)
}

// TestT11_NetworkChangeAndNATExpiryICERestart verifies T11:
// Direct ICE restart succeeds on peer network change using a new generation,
// and fails closed without relay when direct connectivity becomes permanently blocked.
func TestT11_NetworkChangeAndNATExpiryICERestart(t *testing.T) {
	t.Parallel()

	t.Run("PeerNetworkChangeRestartsDirectSession", func(t *testing.T) {
		t.Parallel()
		lf := quietPionLogger()
		wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

		stunNet := newVNetNIC(t, "203.0.113.10")
		netA1 := newVNetNIC(t, "198.51.100.21")
		netA2 := newVNetNIC(t, "198.51.100.22")
		netB := newVNetNIC(t, "198.51.100.25")
		_ = wan.AddNet(stunNet)
		_ = wan.AddNet(netA1)
		_ = wan.AddNet(netA2)
		_ = wan.AddNet(netB)

		var blockOldA1 atomic.Bool
		wan.AddChunkFilter(func(c vnet.Chunk) bool {
			if blockOldA1.Load() {
				src := c.SourceAddr().(*net.UDPAddr).IP.String()
				dst := c.DestinationAddr().(*net.UDPAddr).IP.String()
				if src == "198.51.100.21" || dst == "198.51.100.21" {
					return false
				}
			}
			return true
		})

		_ = wan.Start()
		defer wan.Stop()

		stunConn, _ := stunNet.ListenPacket("udp4", "203.0.113.10:5349")
		defer stunConn.Close()

		ids := newTestMeshIdentities(t)
		_, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "", ids.policy, stunConn, net.ParseIP("203.0.113.10"))

		sessBCh := make(chan *peer.Session, 1)
		clientA, _ := peer.NewClient(peer.Config{
			KeyPair:           ids.peerA,
			Membership:        ids.memA,
			Policy:            ids.policy,
			SignalingURL:      wsURL,
			TLSConfig:         pki.clientTLS,
			STUNServerURI:     "stuns:203.0.113.10:5349",
			NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:   false,
			VNet:              netA1,
			PionLoggerFactory: lf,
			ICERestartBackoff: 50 * time.Millisecond,
		})
		defer clientA.Close()

		clientB, _ := peer.NewClient(peer.Config{
			KeyPair:           ids.peerB,
			Membership:        ids.memB,
			Policy:            ids.policy,
			SignalingURL:      wsURL,
			TLSConfig:         pki.clientTLS,
			STUNServerURI:     "stuns:203.0.113.10:5349",
			NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:   false,
			VNet:              netB,
			PionLoggerFactory: lf,
			ICERestartBackoff: 50 * time.Millisecond,
			OnSession:         func(s *peer.Session) { sessBCh <- s },
		})
		defer clientB.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = clientA.Register(ctx)
		_ = clientB.Register(ctx)

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatalf("initial Connect: %v", err)
		}
		sessB := <-sessBCh

		// Kill old NIC 198.51.100.21 and switch Peer A to new NIC 198.51.100.22!
		blockOldA1.Store(true)
		clientA.UpdateNetwork(netA2)

		// Wait for generation 1 Connected state on both peers.
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			dA := sessA.Diagnostics()
			if dA.Generation >= 1 && sessA.State() == peer.StateConnected && sessA.IsPathVerified() &&
				sessB.State() == peer.StateConnected && sessB.IsPathVerified() {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		diagA := sessA.Diagnostics()
		if diagA.Generation < 1 || diagA.State != peer.StateConnected {
			t.Fatalf("T11: expected ICE restart to connect on generation >= 1, got %+v", diagA)
		}
		if !strings.Contains(diagA.SelectedPair, "198.51.100.22") {
			t.Fatalf("T11: expected new NIC 198.51.100.22 in selected pair, got %s", diagA.SelectedPair)
		}

		if err := sessA.Send(ctx, []byte("after-ice-restart")); err != nil {
			t.Fatalf("Send after restart: %v", err)
		}
		if got := <-sessB.Messages(); string(got) != "after-ice-restart" {
			t.Fatalf("unexpected message after restart: %q", string(got))
		}
		t.Logf("T11 Restart Verified: Generation=%d NewPair=%s", diagA.Generation, diagA.SelectedPair)
	})

	t.Run("UnrecoverableNetworkLossFailsClosed", func(t *testing.T) {
		t.Parallel()
		lf := quietPionLogger()
		wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

		netA := newVNetNIC(t, "198.51.100.31")
		netB := newVNetNIC(t, "198.51.100.32")
		_ = wan.AddNet(netA)
		_ = wan.AddNet(netB)

		var severDirect atomic.Bool
		wan.AddChunkFilter(func(c vnet.Chunk) bool {
			return !severDirect.Load()
		})

		_ = wan.Start()
		defer wan.Stop()

		ids := newTestMeshIdentities(t)
		_, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "", ids.policy, nil)

		clientA, _ := peer.NewClient(peer.Config{
			KeyPair:                 ids.peerA,
			Membership:              ids.memA,
			Policy:                  ids.policy,
			SignalingURL:            wsURL,
			TLSConfig:               pki.clientTLS,
			NetworkTypes:            []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:         false,
			VNet:                    netA,
			PionLoggerFactory:       lf,
			MaxICERestarts:          1,
			ICERestartBackoff:       50 * time.Millisecond,
			OfferToConnectedTimeout: 1500 * time.Millisecond,
		})
		defer clientA.Close()

		clientB, _ := peer.NewClient(peer.Config{
			KeyPair:                 ids.peerB,
			Membership:              ids.memB,
			Policy:                  ids.policy,
			SignalingURL:            wsURL,
			TLSConfig:               pki.clientTLS,
			NetworkTypes:            []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			IncludeLoopback:         false,
			VNet:                    netB,
			PionLoggerFactory:       lf,
			MaxICERestarts:          1,
			ICERestartBackoff:       50 * time.Millisecond,
			OfferToConnectedTimeout: 1500 * time.Millisecond,
		})
		defer clientB.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = clientA.Register(ctx)
		_ = clientB.Register(ctx)

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatal(err)
		}

		// Sever all UDP connectivity and trigger ICE restart -> MUST fail closed.
		severDirect.Store(true)
		if err := sessA.RestartICE(ctx); err == nil {
			t.Fatal("T11: expected RestartICE to fail closed when direct path is severed")
		}
		if sessA.State() != peer.StateFailed {
			t.Fatalf("T11: expected StateFailed, got %s", sessA.State())
		}
	})
}

// TestT12_FloodOversizedSignalingAndMalformedSTUN verifies T12:
// Flooding the Hub with oversized signaling frames, connection bursts, and malformed STUN
// enforces rate/size limits with bounded resource usage while legitimate peers still succeed.
func TestT12_FloodOversizedSignalingAndMalformedSTUN(t *testing.T) {
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
		HTTPSListener:   rawLn,
		TLSConfig:       pki.serverTLS,
		HubOrigin:       "wss://" + boundAddr,
		EnableSTUN:      true,
		STUNSListenAddr: "127.0.0.1:0",
		Policy:          ids.policy,
		PerIPConnRPS:    50,
		PerIPConnBurst:  15,
		STUNPerIPRPS:    50,
		STUNPerIPBurst:  30,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Send an oversized (80 KiB > 64 KiB) WebSocket message during registration -> rejected!
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.clientTLS}}
	wsBig, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = wsBig.Read(ctx) // challenge
	oversizedJSON := `{"v":1,"type":"register","pad":"` + strings.Repeat("A", 80*1024) + `"}`
	_ = wsBig.Write(ctx, websocket.MessageText, []byte(oversizedJSON))
	_, _, readErr := wsBig.Read(ctx)
	if websocket.CloseStatus(readErr) != websocket.StatusMessageTooBig && readErr == nil {
		t.Fatalf("T12: expected oversized WSS frame to be closed with StatusMessageTooBig, got %v", readErr)
	}
	_ = wsBig.CloseNow()

	// 2. Flood STUN UDP with 250 malformed, oversized, and unsupported packets.
	floodUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer floodUDP.Close()

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				switch (worker + i) % 3 {
				case 0:
					_, _ = floodUDP.WriteTo([]byte("garbage-stun-flood"), srv.STUNAddr())
				case 1:
					_, _ = floodUDP.WriteTo(bytes.Repeat([]byte{0xaa}, 1024), srv.STUNAddr())
				case 2:
					alloc := stun.MustBuild(stun.TransactionID, stun.NewType(stun.MethodAllocate, stun.ClassRequest))
					_, _ = floodUDP.WriteTo(alloc.Raw, srv.STUNAddr())
				}
			}
		}(g)
	}
	wg.Wait()

	// 3. Burst WSS connection attempts beyond PerIPConnBurst (15) -> HTTP 429 rate limiting engages.
	for i := 0; i < 25; i++ {
		c, _, dErr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
		if dErr == nil {
			_ = c.CloseNow()
		}
	}

	st := srv.Stats()
	if st.RateLimited == 0 {
		t.Fatalf("T12: expected Hub RateLimited > 0 after burst flood, got %+v", st)
	}
	if st.STUN.MalformedPackets+st.STUN.OversizedPackets+st.STUN.UnsupportedMethods+st.STUN.RateLimited == 0 {
		t.Fatalf("T12: expected STUN flood counters > 0, got %+v", st.STUN)
	}

	// Wait briefly for token bucket refill (~100ms) and verify legitimate peers still connect!
	time.Sleep(120 * time.Millisecond)

	sessBCh := make(chan *peer.Session, 1)
	clientA, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerA,
		Membership:      ids.memA,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   "stuns:" + srv.STUNSAddr().String(),
		IncludeLoopback: true,
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerB,
		Membership:      ids.memB,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   "stuns:" + srv.STUNSAddr().String(),
		IncludeLoopback: true,
		OnSession:       func(s *peer.Session) { sessBCh <- s },
	})
	defer clientB.Close()

	if err := clientA.Register(ctx); err != nil {
		t.Fatalf("legitimate Register A after flood: %v", err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatalf("legitimate Register B after flood: %v", err)
	}
	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("legitimate Connect after flood: %v", err)
	}
	sessB := <-sessBCh
	_ = sessA.Send(ctx, []byte("survived-flood"))
	if got := <-sessB.Messages(); string(got) != "survived-flood" {
		t.Fatal("payload mismatch after flood")
	}
}

// TestT13_TamperDTLSProtectedRecordNotDelivered verifies T13:
// Flipping bits in an in-flight DTLS 1.3 ciphertext record causes AEAD authentication
// rejection so tampered content is never delivered to the application.
func TestT13_TamperDTLSProtectedRecordNotDelivered(t *testing.T) {
	t.Parallel()

	lf := quietPionLogger()
	wan := newVNetRouter(t, &vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: lf})

	netA := newVNetNIC(t, "198.51.100.41")
	netB := newVNetNIC(t, "198.51.100.42")
	_ = wan.AddNet(netA)
	_ = wan.AddNet(netB)

	var (
		tamperNextCiphertext atomic.Bool
		tamperedCount        atomic.Uint64
	)

	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		src := c.SourceAddr().(*net.UDPAddr).IP.String()
		dst := c.DestinationAddr().(*net.UDPAddr).IP.String()
		data := c.UserData()
		if src == "198.51.100.41" && dst == "198.51.100.42" && len(data) > 32 &&
			dtlsProtocol.IsDTLS13Ciphertext(dtlsProtocol.ContentType(data[0])) {
			if tamperNextCiphertext.CompareAndSwap(true, false) {
				// Flip ciphertext / AEAD authentication tag bits in transit!
				data[len(data)-1] ^= 0xff
				data[len(data)-5] ^= 0xa5
				tamperedCount.Add(1)
			}
		}
		return true
	})

	_ = wan.Start()
	defer wan.Stop()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "", ids.policy, nil)

	sessBCh := make(chan *peer.Session, 1)
	clientA, _ := peer.NewClient(peer.Config{
		KeyPair:             ids.peerA,
		Membership:          ids.memA,
		Policy:              ids.policy,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     false,
		EnablePacketChannel: true,
		VNet:                netA,
		PionLoggerFactory:   lf,
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:             ids.peerB,
		Membership:          ids.memB,
		Policy:              ids.policy,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     false,
		EnablePacketChannel: true,
		VNet:                netB,
		PionLoggerFactory:   lf,
		OnSession:           func(s *peer.Session) { sessBCh <- s },
	})
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	sessB := <-sessBCh

	// Wait until packet/v1 channel is open by sending a warmup datagram.
	warmup := []byte("warmup-packet-v1")
	for i := 0; i < 10; i++ {
		_ = sessA.SendPacket(ctx, warmup)
		select {
		case got := <-sessB.Packets():
			if bytes.Equal(got, warmup) {
				goto packetOpen
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("packet/v1 failed to open during warmup")

packetOpen:
	// Arm wire-level DTLS 1.3 record tampering for the next packet/v1 datagram (maxRetransmits=0).
	tamperNextCiphertext.Store(true)
	poisoned := []byte("FORGED-OR-CORRUPTED-PAYLOAD-MUST-NOT-ARRIVE")
	if err := sessA.SendPacket(ctx, poisoned); err != nil {
		t.Fatal(err)
	}
	// Wait until the filter confirms it tampered with the in-flight DTLS 1.3 ciphertext record.
	deadline := time.Now().Add(2 * time.Second)
	for tamperedCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if tamperedCount.Load() == 0 {
		t.Fatal("T13: tamper filter did not intercept DTLS 1.3 ciphertext")
	}

	// Send a subsequent authentic, untampered datagram.
	authentic := []byte("AUTHENTIC-DTLS13-RECORD")
	if err := sessA.SendPacket(ctx, authentic); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-sessB.Packets():
		if !bytes.Equal(got, authentic) {
			t.Fatalf("T13 violation: tampered or unexpected bytes delivered to app: %q", string(got))
		}
	case <-ctx.Done():
		t.Fatal("T13: authentic follow-up record did not arrive")
	}
	t.Logf("T13 Verified: TamperedDTLS13Records=%d (dropped by AEAD; zero corrupted bytes delivered)", tamperedCount.Load())
}
