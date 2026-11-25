package acceptance_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/protocol"
)

func findNonLinkLocalIPv6() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip := ipNet.IP
			if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() {
				return ip
			}
		}
	}
	return nil
}

// TestTCPOnlyModeZeroUDPEndToEnd verifies opt-in --tcp-only mode across hub and peers.
func TestTCPOnlyModeZeroUDPEndToEnd(t *testing.T) {
	t.Parallel()

	t.Run("HubAndPeerConfigGuardrails", func(t *testing.T) {
		t.Parallel()
		ids := newTestMeshIdentities(t)
		pki := generateTestPKI(t)

		rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rawLn.Close()
		udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer udpConn.Close()

		if _, err := hub.New(&hub.Config{
			HTTPSListener:   rawLn,
			TLSConfig:       pki.serverTLS,
			HubOrigin:       "wss://" + rawLn.Addr().String(),
			TCPOnly:         true,
			STUNSPacketConn: udpConn,
		}); err == nil {
			t.Fatal("expected hub.New to reject UDP PacketConn when TCPOnly=true")
		}

		for _, badCfg := range []peer.Config{
			{
				KeyPair:      ids.peerA,
				SignalingURL: "wss://127.0.0.1:8443/v1/signal",
				TCPOnly:      true,
				NetworkTypes: []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
			},
			{
				KeyPair:       ids.peerA,
				SignalingURL:  "wss://127.0.0.1:8443/v1/signal",
				TCPOnly:       true,
				STUNServerURI: "stuns:127.0.0.1:5349?transport=udp",
			},
			{
				KeyPair:            ids.peerA,
				SignalingURL:       "wss://127.0.0.1:8443/v1/signal",
				TCPOnly:            true,
				ICETransportPolicy: webrtc.ICETransportPolicyRelay,
			},
			{
				KeyPair:       ids.peerA,
				SignalingURL:  "wss://127.0.0.1:8443/v1/signal",
				TCPOnly:       true,
				STUNServerURI: "stun:127.0.0.1:3478",
			},
		} {
			if _, err := peer.NewClient(&badCfg); !errors.Is(err, peer.ErrInvalidICEConfig) {
				t.Fatalf("expected ErrInvalidICEConfig for TCP-only invalid config %+v, got %v", badCfg, err)
			}
		}
	})

	t.Run("IPv4_DefaultConfig_ICETCP_DTLS13", func(t *testing.T) {
		t.Parallel()
		ids := newTestMeshIdentities(t)
		pki := generateTestPKI(t)

		httpsLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		stunsLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			_ = httpsLn.Close()
			t.Fatal(err)
		}

		boundHTTPS := httpsLn.Addr().String()
		wsURL := "wss://" + boundHTTPS + "/v1/signal"

		srv, err := hub.New(&hub.Config{
			HTTPSListener:    httpsLn,
			TLSConfig:        pki.serverTLS,
			HubOrigin:        "wss://" + boundHTTPS,
			TCPOnly:          true,
			EnableSTUN:       true,
			STUNSTLSListener: stunsLn,
		})
		if err != nil {
			_ = httpsLn.Close()
			_ = stunsLn.Close()
			t.Fatalf("hub.New TCPOnly: %v", err)
		}
		defer srv.Close()

		if !srv.TCPOnly() || srv.STUNSDTLSAddr() != nil || srv.STUNUDPAddr() != nil || srv.STUNTCPAddr() != nil || srv.STUNSTLSAddr() == nil {
			t.Fatalf("expected strict TCP-only hub (zero UDP), got tcpOnly=%v dtls=%v udp=%v tcp=%v tls=%v",
				srv.TCPOnly(), srv.STUNSDTLSAddr(), srv.STUNUDPAddr(), srv.STUNTCPAddr(), srv.STUNSTLSAddr())
		}

		stunsURI := "stuns:" + srv.STUNSTLSAddr().String()

		untrustedClient, err := peer.NewClient(&peer.Config{
			KeyPair:       ids.peerA,
			SignalingURL:  wsURL,
			TLSConfig:     &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()},
			STUNServerURI: stunsURI,
			TCPOnly:       true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer untrustedClient.Close()
		probeFailCtx, probeFailCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if _, err := untrustedClient.ProbeSTUNS(probeFailCtx); err == nil {
			probeFailCancel()
			t.Fatal("expected TLS 1.3/TCP ProbeSTUNS to reject untrusted CA")
		}
		probeFailCancel()

		sessBCh := make(chan *peer.Session, 1)
		clientA, err := peer.NewClient(&peer.Config{
			KeyPair:             ids.peerA,
			SignalingURL:        wsURL,
			TLSConfig:           pki.clientTLS,
			STUNServerURI:       stunsURI,
			TCPOnly:             true,
			IncludeLoopback:     true,
			EnablePacketChannel: true,
			Consent:             allowAllConsent(),
		})
		if err != nil {
			t.Fatalf("NewClient A TCPOnly: %v", err)
		}
		defer clientA.Close()

		clientB, err := peer.NewClient(&peer.Config{
			KeyPair:             ids.peerB,
			SignalingURL:        wsURL,
			TLSConfig:           pki.clientTLS,
			STUNServerURI:       stunsURI,
			TCPOnly:             true,
			IncludeLoopback:     true,
			EnablePacketChannel: true,
			Consent:             allowAllConsent(),
			OnSession:           func(s *peer.Session) { sessBCh <- s },
		})
		if err != nil {
			t.Fatalf("NewClient B TCPOnly: %v", err)
		}
		defer clientB.Close()

		if clientA.ICETCPAddr() == nil || clientB.ICETCPAddr() == nil {
			t.Fatal("expected passive ICE-TCP listener bound on both TCP-only clients")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		mapped, err := clientA.ProbeSTUNS(ctx)
		if err != nil || mapped == nil {
			t.Fatalf("ProbeSTUNS over TLS 1.3/TCP failed: mapped=%v err=%v", mapped, err)
		}
		if err := clientA.Register(ctx); err != nil {
			t.Fatalf("Register A: %v", err)
		}
		if err := clientB.Register(ctx); err != nil {
			t.Fatalf("Register B: %v", err)
		}

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatalf("Connect A->B in TCP-only mode failed: %v", err)
		}
		var sessB *peer.Session
		select {
		case sessB = <-sessBCh:
		case <-ctx.Done():
			t.Fatal("timeout waiting for responder session B in TCP-only mode")
		}

		diagA := sessA.Diagnostics()
		if diagA.DTLSVersion != peer.ExpectedDTLS13HexVersion {
			t.Fatalf("expected DTLS 1.3 (FEFC) over ICE-TCP, got %q", diagA.DTLSVersion)
		}
		if diagA.LocalCandidateType != "host" || diagA.RemoteCandidateType != "host" {
			t.Fatalf("expected host-host ICE-TCP pair, got (%s, %s)", diagA.LocalCandidateType, diagA.RemoteCandidateType)
		}
		if !strings.Contains(strings.ToLower(diagA.SelectedPair), "tcp") {
			t.Fatalf("expected TCP selected candidate pair, got %q", diagA.SelectedPair)
		}

		msgAB := []byte("tcp-only-data-A-to-B")
		msgBA := []byte("tcp-only-data-B-to-A")
		if err := sessA.Send(ctx, msgAB); err != nil {
			t.Fatal(err)
		}
		if got := <-sessB.Messages(); !bytes.Equal(got, msgAB) {
			t.Fatalf("A->B mismatch: got %q want %q", string(got), string(msgAB))
		}
		if err := sessB.Send(ctx, msgBA); err != nil {
			t.Fatal(err)
		}
		if got := <-sessA.Messages(); !bytes.Equal(got, msgBA) {
			t.Fatalf("B->A mismatch: got %q want %q", string(got), string(msgBA))
		}

		pkt := []byte("tcp-only-packet-v1")
		if err := sessA.SendPacket(ctx, pkt); err != nil {
			t.Fatal(err)
		}
		select {
		case gotPkt := <-sessB.Packets():
			if !bytes.Equal(gotPkt, pkt) {
				t.Fatalf("packet mismatch: got %q want %q", string(gotPkt), string(pkt))
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timeout waiting for packet/v1 payload in TCP-only mode")
		}

		fakePC, err := webrtc.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fakePC.CreateDataChannel("data/v1", nil)
		baseOffer, err := fakePC.CreateOffer(nil)
		_ = fakePC.Close()
		if err != nil {
			t.Fatal(err)
		}
		udpSDP := baseOffer.SDP + "a=candidate:99 1 UDP 2130706431 127.0.0.1 45000 typ host\r\n"

		rejectClient, err := peer.NewClient(&peer.Config{
			KeyPair:       ids.peerA,
			SignalingURL:  wsURL,
			TLSConfig:     pki.clientTLS,
			STUNServerURI: stunsURI,
			TCPOnly:       true,
			Consent:       allowAllConsent(),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer rejectClient.Close()

		sid, err := protocol.NewSessionID()
		if err != nil {
			t.Fatal(err)
		}
		_, rawUDPOffer, err := protocol.SignEnvelope(
			ids.peerB,
			protocol.TypeOffer,
			ids.peerA.PeerID,
			sid,
			0,
			0,
			time.Now().Add(time.Minute).Unix(),
			protocol.SDPBody{SDP: udpSDP},
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := rejectClient.InjectRawEnvelopeForTesting(rawUDPOffer); !errors.Is(err, peer.ErrProhibitedCandidate) {
			t.Fatalf("expected ErrProhibitedCandidate for UDP SDP offer in TCP-only mode, got %v", err)
		}
		if rejectClient.ProhibitedCandidateCount() == 0 {
			t.Fatal("expected ProhibitedCandidateCount > 0 after rejecting UDP candidate in TCP-only mode")
		}

		t.Logf("Verified IPv4 TCP-only: Pair=%s DTLS=%s", diagA.SelectedPair, diagA.DTLSVersion)
	})

	t.Run("IPv6_TLS13STUNS_And_ICETCP", func(t *testing.T) {
		t.Parallel()
		httpsLn, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		stunsLn, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			_ = httpsLn.Close()
			t.Fatal(err)
		}

		ids := newTestMeshIdentities(t)
		nonLLIPv6 := findNonLinkLocalIPv6()
		var extraSANs []net.IP
		if nonLLIPv6 != nil {
			extraSANs = append(extraSANs, nonLLIPv6)
		}
		pki := generateTestPKI(t, extraSANs...)

		boundHTTPS := httpsLn.Addr().String()
		wsURL := "wss://" + boundHTTPS + "/v1/signal"

		srv, err := hub.New(&hub.Config{
			HTTPSListener:    httpsLn,
			TLSConfig:        pki.serverTLS,
			HubOrigin:        "wss://" + boundHTTPS,
			TCPOnly:          true,
			EnableSTUN:       true,
			STUNSTLSListener: stunsLn,
		})
		if err != nil {
			_ = httpsLn.Close()
			_ = stunsLn.Close()
			t.Fatalf("hub.New IPv6 TCPOnly: %v", err)
		}
		defer srv.Close()

		if srv.STUNSDTLSAddr() != nil || srv.STUNUDPAddr() != nil || srv.STUNSTLSAddr() == nil {
			t.Fatalf("expected IPv6 TCP-only hub (zero UDP), got dtls=%v udp=%v tls=%v",
				srv.STUNSDTLSAddr(), srv.STUNUDPAddr(), srv.STUNSTLSAddr())
		}

		stunsURI := "stuns:" + srv.STUNSTLSAddr().String()
		sessBCh := make(chan *peer.Session, 1)
		clientA, err := peer.NewClient(&peer.Config{
			KeyPair:       ids.peerA,
			SignalingURL:  wsURL,
			TLSConfig:     pki.clientTLS,
			STUNServerURI: stunsURI,
			TCPOnly:       true,
			NetworkTypes:  []webrtc.NetworkType{webrtc.NetworkTypeTCP6},
			Consent:       allowAllConsent(),
		})
		if err != nil {
			t.Fatalf("NewClient A IPv6 TCPOnly: %v", err)
		}
		defer clientA.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		mapped, err := clientA.ProbeSTUNS(ctx)
		if err != nil || mapped == nil || !mapped.IP.Equal(net.IPv6loopback) {
			t.Fatalf("IPv6 TLS 1.3/TCP ProbeSTUNS failed: mapped=%v err=%v", mapped, err)
		}
		if err := clientA.Register(ctx); err != nil {
			t.Fatalf("IPv6 Register A: %v", err)
		}

		if nonLLIPv6 == nil {
			t.Log("IPv6 TLS 1.3 WSS + TLS 1.3/TCP STUNS verified on [::1]; skipping TCP6 ICE-TCP connect (no non-link-local IPv6 address on host)")
			return
		}

		clientB, err := peer.NewClient(&peer.Config{
			KeyPair:       ids.peerB,
			SignalingURL:  wsURL,
			TLSConfig:     pki.clientTLS,
			STUNServerURI: stunsURI,
			TCPOnly:       true,
			NetworkTypes:  []webrtc.NetworkType{webrtc.NetworkTypeTCP6},
			Consent:       allowAllConsent(),
			OnSession:     func(s *peer.Session) { sessBCh <- s },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clientB.Close()
		if err := clientB.Register(ctx); err != nil {
			t.Fatal(err)
		}

		sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
		if err != nil {
			t.Fatalf("IPv6 ICE-TCP connect failed: %v", err)
		}
		sessB := <-sessBCh
		if err := sessA.Send(ctx, []byte("ipv6-tcp-only-ok")); err != nil {
			t.Fatal(err)
		}
		if got := <-sessB.Messages(); string(got) != "ipv6-tcp-only-ok" {
			t.Fatalf("unexpected IPv6 TCP-only payload %q", string(got))
		}
	})
}
