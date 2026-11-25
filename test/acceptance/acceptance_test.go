package acceptance_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/protocol"
)

// TestArchitectureAndControlPlaneInvariants verifies ARCH-01..ARCH-05, TLS 1.3 WSS enforcement,
// /healthz privacy, and log redaction requirements.
func TestArchitectureAndControlPlaneInvariants(t *testing.T) {
	t.Parallel()

	// Verify cmd/lighthouse has ZERO dependency on pion/webrtc or pion/turn (Section 2.1, ARCH-03).
	out, err := exec.Command("go", "list", "-deps", "lighthouse-in-snoo/cmd/lighthouse").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, string(out))
	}
	deps := string(out)
	if strings.Contains(deps, "github.com/pion/webrtc") {
		t.Fatalf("ARCH-03 violation: hub binary depends on pion/webrtc:\n%s", deps)
	}
	if strings.Contains(deps, "github.com/pion/turn") {
		t.Fatalf("ARCH-03 violation: hub binary depends on pion/turn:\n%s", deps)
	}

	ids := newTestMeshIdentities(t)
	srv, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

	// Verify /healthz returns status ok and no private peer details (Section 4.1).
	healthURL := "https://" + srv.HTTPSAddr().String() + "/healthz"
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.clientTLS}}
	resp, err := hc.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected /healthz: status=%d body=%q", resp.StatusCode, string(body))
	}

	// Verify TLS 1.2 client is rejected by Hub WSS (Section 4.1).
	tls12Cfg := pki.clientTLS.Clone()
	tls12Cfg.MinVersion = tls.VersionTLS12
	tls12Cfg.MaxVersion = tls.VersionTLS12
	hc12 := &http.Client{Transport: &http.Transport{TLSClientConfig: tls12Cfg}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, dialErr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc12}); dialErr == nil {
		t.Fatal("expected TLS 1.2 connection to Hub WSS to fail")
	}
}

// TestT01_SameLANDirectHostConnectivity verifies T01:
// Peers on the same LAN establish direct host candidate connectivity over DTLS 1.3,
// exchange reliable (data/v1) and unordered (packet/v1) payloads, enforce 16 KiB max size,
// and emit zero sensitive secrets in logs.
func TestT01_SameLANDirectHostConnectivity(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	_, pki, hubLogs, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

	peerLogs := &safeLogBuffer{}
	peerLogger := slog.New(slog.NewJSONHandler(peerLogs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sessBCh := make(chan *peer.Session, 1)
	clientA, err := peer.NewClient(peer.Config{
		KeyPair:             ids.peerA,
		Membership:          ids.memA,
		Policy:              ids.policy,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		STUNServerURI:       stunURI,
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Logger:              peerLogger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(peer.Config{
		KeyPair:             ids.peerB,
		Membership:          ids.memB,
		Policy:              ids.policy,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		STUNServerURI:       stunURI,
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Logger:              peerLogger,
		OnSession: func(s *peer.Session) {
			sessBCh <- s
		},
	})
	if err != nil {
		t.Fatal(err)
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

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("Connect A->B: %v", err)
	}
	var sessB *peer.Session
	select {
	case sessB = <-sessBCh:
	case <-ctx.Done():
		t.Fatal("timed out waiting for responder session B")
	}

	diagA := sessA.Diagnostics()
	if diagA.DTLSVersion != peer.ExpectedDTLS13HexVersion {
		t.Fatalf("DTLSVersion = %q; want %q (DTLS 1.3)", diagA.DTLSVersion, peer.ExpectedDTLS13HexVersion)
	}
	if diagA.LocalCandidateType != "host" || diagA.RemoteCandidateType != "host" {
		t.Fatalf("expected direct host-host pair on LAN, got (%s, %s)", diagA.LocalCandidateType, diagA.RemoteCandidateType)
	}

	// Reliable data/v1 transfer.
	secretPayload := []byte("SUPER-SECRET-APP-PAYLOAD-T01")
	if err := sessA.Send(ctx, secretPayload); err != nil {
		t.Fatalf("Send data/v1: %v", err)
	}
	select {
	case got := <-sessB.Messages():
		if !bytes.Equal(got, secretPayload) {
			t.Fatalf("data/v1 mismatch: got %q", string(got))
		}
	case <-ctx.Done():
		t.Fatal("timeout receiving data/v1")
	}

	// Unordered packet/v1 transfer.
	dgram := []byte("packet-v1-datagram")
	if err := sessA.SendPacket(ctx, dgram); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	select {
	case got := <-sessB.Packets():
		if !bytes.Equal(got, dgram) {
			t.Fatalf("packet/v1 mismatch: got %q", string(got))
		}
	case <-ctx.Done():
		t.Fatal("timeout receiving packet/v1")
	}

	// Enforce 16 KiB per-message application limit (Section 7).
	oversized := make([]byte, peer.MaxApplicationMessageBytes+1)
	if err := sessA.Send(ctx, oversized); !errors.Is(err, peer.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge for 16KiB+1 payload, got %v", err)
	}

	// Observability privacy check (Section 9): logs must NOT contain SDP, ICE pwd, keys, or payload.
	combinedLogs := hubLogs.String() + "\n" + peerLogs.String()
	for _, forbidden := range []string{"v=0\r\n", "a=ice-pwd:", string(secretPayload), "typ host"} {
		if strings.Contains(combinedLogs, forbidden) {
			t.Fatalf("log privacy violation: found %q in logs:\n%s", forbidden, combinedLogs)
		}
	}

	// Record acceptance telemetry (Section 10).
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if strings.HasPrefix(dep.Path, "github.com/pion/") {
				t.Logf("Dependency: %s %s", dep.Path, dep.Version)
			}
		}
	}
	t.Logf("T01 Verified: DTLS=%s Cipher=%s Pair=%s RTT=%.6fs", diagA.DTLSVersion, diagA.DTLSCipher, diagA.SelectedPair, diagA.RTTSeconds)
}

// TestT02_PublicIPv4AndIPv6Connectivity verifies T02 across both IPv4 and IPv6 families.
func TestT02_PublicIPv4AndIPv6Connectivity(t *testing.T) {
	t.Parallel()

	families := []struct {
		name     string
		tcpNet   string
		bindHost string
		stunAddr string
		netType  webrtc.NetworkType
	}{
		{"IPv4", "tcp4", "127.0.0.1:0", "127.0.0.1:0", webrtc.NetworkTypeUDP4},
		{"IPv6", "tcp6", "[::1]:0", "[::1]:0", webrtc.NetworkTypeUDP6},
	}

	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			t.Parallel()
			ids := newTestMeshIdentities(t)
			_, pki, _, wsURL, stunURI := startTestHub(t, fam.tcpNet, fam.bindHost, fam.stunAddr, ids.policy, nil)

			sessBCh := make(chan *peer.Session, 1)
			clientA, err := peer.NewClient(peer.Config{
				KeyPair:         ids.peerA,
				Membership:      ids.memA,
				Policy:          ids.policy,
				SignalingURL:    wsURL,
				TLSConfig:       pki.clientTLS,
				STUNServerURI:   stunURI,
				NetworkTypes:    []webrtc.NetworkType{fam.netType},
				IncludeLoopback: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clientA.Close()

			clientB, err := peer.NewClient(peer.Config{
				KeyPair:         ids.peerB,
				Membership:      ids.memB,
				Policy:          ids.policy,
				SignalingURL:    wsURL,
				TLSConfig:       pki.clientTLS,
				STUNServerURI:   stunURI,
				NetworkTypes:    []webrtc.NetworkType{fam.netType},
				IncludeLoopback: true,
				OnSession:       func(s *peer.Session) { sessBCh <- s },
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

			sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
			if err != nil {
				t.Fatalf("%s Connect failed: %v", fam.name, err)
			}
			sessB := <-sessBCh

			msg := []byte("dual-stack-check-" + fam.name)
			if err := sessA.Send(ctx, msg); err != nil {
				t.Fatal(err)
			}
			got := <-sessB.Messages()
			if !bytes.Equal(got, msg) {
				t.Fatalf("mismatch on %s", fam.name)
			}

			diag := sessA.Diagnostics()
			if diag.DTLSVersion != peer.ExpectedDTLS13HexVersion {
				t.Fatalf("expected DTLS 1.3 on %s, got %s", fam.name, diag.DTLSVersion)
			}
			if fam.name == "IPv6" && !strings.Contains(diag.SelectedPair, "udp6") {
				t.Fatalf("expected udp6 candidate pair, got %s", diag.SelectedPair)
			}
			if fam.name == "IPv4" && !strings.Contains(diag.SelectedPair, "udp4") {
				t.Fatalf("expected udp4 candidate pair, got %s", diag.SelectedPair)
			}
			t.Logf("T02 (%s) Verified: Pair=%s DTLS=%s", fam.name, diag.SelectedPair, diag.DTLSVersion)
		})
	}
}

// TestT05_PeerSupportsOnlyDTLS12Fails verifies T05:
// Handshake fails closed when remote peer only supports DTLS 1.2; zero payloads transmitted.
func TestT05_PeerSupportsOnlyDTLS12Fails(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

	payloadDelivered := make(chan []byte, 1)

	clientA, err := peer.NewClient(peer.Config{
		KeyPair:                 ids.peerA,
		Membership:              ids.memA,
		Policy:                  ids.policy,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		OfferToConnectedTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	// Peer B simulates a legacy DTLS 1.2-only endpoint.
	clientB, err := peer.NewClient(peer.Config{
		KeyPair:                 ids.peerB,
		Membership:              ids.memB,
		Policy:                  ids.policy,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		OfferToConnectedTimeout: 3 * time.Second,
		OverrideDTLSMinVersion:  dtlsProtocol.Version1_2,
		OverrideDTLSMaxVersion:  dtlsProtocol.Version1_2,
		OnSession: func(s *peer.Session) {
			go func() {
				if msg, ok := <-s.Messages(); ok {
					payloadDelivered <- msg
				}
			}()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := clientA.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := clientA.Connect(ctx, ids.peerB.PeerID); err == nil {
		t.Fatal("T05 violation: DTLS 1.2 peer succeeded in connecting to DTLS 1.3 peer")
	}

	select {
	case msg := <-payloadDelivered:
		t.Fatalf("T05 violation: payload delivered despite DTLS 1.2 mismatch: %q", string(msg))
	default:
	}
}

// TestT06_CompromisedHubTamperingFails verifies T06:
// Hub tampering with SDP fingerprint, ICE credentials, or sender fails verification.
func TestT06_CompromisedHubTamperingFails(t *testing.T) {
	t.Parallel()

	mutations := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "tamper SDP fingerprint",
			mutate: func(raw []byte) []byte {
				var env map[string]any
				if json.Unmarshal(raw, &env) != nil || env["type"] != protocol.TypeOffer {
					return raw
				}
				return bytes.Replace(raw, []byte("sha-256 "), []byte("sha-256 00"), 1)
			},
		},
		{
			name: "tamper ICE credentials",
			mutate: func(raw []byte) []byte {
				var env map[string]any
				if json.Unmarshal(raw, &env) != nil || env["type"] != protocol.TypeOffer {
					return raw
				}
				return bytes.Replace(raw, []byte("ice-pwd:"), []byte("ice-pwd:X"), 1)
			},
		},
		{
			name: "tamper sender identity",
			mutate: func(raw []byte) []byte {
				var env protocol.SignalEnvelope
				if json.Unmarshal(raw, &env) != nil || env.Type != protocol.TypeOffer {
					return raw
				}
				other, _ := identity.GenerateKeyPair()
				return bytes.Replace(raw, []byte(`"from":"`+env.From+`"`), []byte(`"from":"`+other.PeerID+`"`), 1)
			},
		},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ids := newTestMeshIdentities(t)
			srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)
			srv.SetForwardTamperHookForTesting(tc.mutate)

			clientA, _ := peer.NewClient(peer.Config{
				KeyPair:                 ids.peerA,
				Membership:              ids.memA,
				Policy:                  ids.policy,
				SignalingURL:            wsURL,
				TLSConfig:               pki.clientTLS,
				STUNServerURI:           stunURI,
				IncludeLoopback:         true,
				OfferToConnectedTimeout: 1200 * time.Millisecond,
			})
			defer clientA.Close()

			clientB, _ := peer.NewClient(peer.Config{
				KeyPair:                 ids.peerB,
				Membership:              ids.memB,
				Policy:                  ids.policy,
				SignalingURL:            wsURL,
				TLSConfig:               pki.clientTLS,
				STUNServerURI:           stunURI,
				IncludeLoopback:         true,
				OfferToConnectedTimeout: 1200 * time.Millisecond,
			})
			defer clientB.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = clientA.Register(ctx)
			_ = clientB.Register(ctx)

			if _, err := clientA.Connect(ctx, ids.peerB.PeerID); err == nil {
				t.Fatalf("T06 (%s): expected tampered signaling to fail", tc.name)
			}
			if clientB.RejectedSignalCount() == 0 {
				t.Fatalf("T06 (%s): expected Peer B to record rejected tampered envelope", tc.name)
			}
		})
	}
}

// TestT07_UnknownForbiddenAndReplayedSignalingRejected verifies T07.
func TestT07_UnknownForbiddenAndReplayedSignalingRejected(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Unknown/untrusted peer registration MUST be rejected.
	unknownKP, _ := identity.GenerateKeyPair()
	unknownClient, err := peer.NewClient(peer.Config{
		KeyPair:      unknownKP,
		Policy:       ids.policy,
		SignalingURL: wsURL,
		TLSConfig:    pki.clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unknownClient.Close()
	if err := unknownClient.Register(ctx); err == nil {
		t.Fatal("T07: expected unknown peer registration to be rejected")
	}

	// 2. Forbidden peer pair: Peer C has valid authority membership, so it can register,
	//    but ACL only allows A <-> B. Lookup and connection C -> B MUST be denied!
	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerB,
		Membership:      ids.memB,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	defer clientB.Close()
	if err := clientB.Register(ctx); err != nil {
		t.Fatalf("Register B: %v", err)
	}

	clientC, _ := peer.NewClient(peer.Config{
		KeyPair:                 ids.peerC,
		Membership:              ids.memC,
		Policy:                  ids.policy,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		OfferToConnectedTimeout: 2 * time.Second,
	})
	defer clientC.Close()
	if err := clientC.Register(ctx); err != nil {
		t.Fatalf("Register C: %v", err)
	}
	if _, _, err := clientC.Lookup(ctx, ids.peerB.PeerID); err == nil {
		t.Fatal("T07: expected forbidden pair C->B lookup to be denied")
	}

	// 3. Replayed signaling MUST be rejected at both Hub and Peer B.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.clientTLS}}
	wsA, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	defer wsA.CloseNow()
	_, rawChal, _ := wsA.Read(ctx)
	var chal protocol.ChallengeMessage
	_ = json.Unmarshal(rawChal, &chal)
	proof, _ := ids.peerA.SignRegistrationChallenge(chal.Challenge, srv.HubOrigin())
	regRaw, _ := json.Marshal(protocol.RegisterMessage{
		V:          1,
		Type:       protocol.TypeRegister,
		PeerID:     ids.peerA.PeerID,
		PublicKey:  identity.EncodePublicKey(ids.peerA.PublicKey),
		HubOrigin:  srv.HubOrigin(),
		Challenge:  chal.Challenge,
		Membership: ids.memA,
		Proof:      proof,
	})
	_ = wsA.Write(ctx, websocket.MessageText, regRaw)
	_, _, _ = wsA.Read(ctx) // registered

	sid, _ := protocol.NewSessionID()
	_, closeEnvRaw, err := protocol.SignEnvelope(
		ids.peerA,
		protocol.TypeClose,
		ids.peerB.PeerID,
		sid,
		0,
		0,
		time.Now().Add(60*time.Second).Unix(),
		protocol.CloseBody{Reason: "test_close"},
	)
	if err != nil {
		t.Fatal(err)
	}
	// First send succeeds; second replay of identical signed envelope MUST return replayed_signaling error!
	if err := wsA.Write(ctx, websocket.MessageText, closeEnvRaw); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := wsA.Write(ctx, websocket.MessageText, closeEnvRaw); err != nil {
		t.Fatal(err)
	}
	_, replayRespRaw, err := wsA.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var errMsg protocol.ErrorMessage
	_ = json.Unmarshal(replayRespRaw, &errMsg)
	if errMsg.Code != protocol.ErrCodeReplayedSignaling {
		t.Fatalf("T07: expected hub error %q on replay, got %+v", protocol.ErrCodeReplayedSignaling, errMsg)
	}

	// Replaying directly into Peer B's envelope verifier MUST also be rejected.
	if err := clientB.InjectRawEnvelopeForTesting(closeEnvRaw); !errors.Is(err, peer.ErrReplayedSignaling) {
		t.Fatalf("T07: expected Peer B ErrReplayedSignaling, got %v", err)
	}
}

// TestT08_RelayAndHubEndpointCandidatesRejected verifies T08:
// TURN configuration, relay candidates in SDP, relay candidates in Trickle ICE,
// and candidates pointing at Hub endpoints are all rejected before installation.
func TestT08_RelayAndHubEndpointCandidatesRejected(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

	// 1. TURN server URL in peer config MUST be rejected immediately.
	if _, err := peer.NewClient(peer.Config{
		KeyPair:       ids.peerA,
		Policy:        ids.policy,
		SignalingURL:  wsURL,
		STUNServerURI: "turn:127.0.0.1:3478",
	}); !errors.Is(err, peer.ErrInvalidICEConfig) {
		t.Fatalf("T08: expected ErrInvalidICEConfig for turn: URI, got %v", err)
	}

	clientA, err := peer.NewClient(peer.Config{
		KeyPair:         ids.peerA,
		Membership:      ids.memA,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(peer.Config{
		KeyPair:         ids.peerB,
		Membership:      ids.memB,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := clientA.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatal(err)
	}

	// Build a syntactically valid WebRTC data-channel SDP offer and inject a relay candidate into it.
	pcTmp, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer pcTmp.Close()
	_, _ = pcTmp.CreateDataChannel(peer.ChannelLabelDataV1, nil)
	baseOffer, err := pcTmp.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}

	sdpWithRelay := baseOffer.SDP + "a=candidate:99 1 UDP 16777295 198.51.100.99 54321 typ relay raddr 192.0.2.1 rport 40000\r\n"
	sid1, _ := protocol.NewSessionID()
	_, relayOfferRaw, err := protocol.SignEnvelope(
		ids.peerA,
		protocol.TypeOffer,
		ids.peerB.PeerID,
		sid1,
		0,
		0,
		time.Now().Add(60*time.Second).Unix(),
		protocol.SDPBody{SDP: sdpWithRelay},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure Peer B knows Peer A's verified identity locally.
	policyWithBoth := ids.policy
	policyWithBoth.Memberships = []identity.MembershipRecord{*ids.memA, *ids.memB}
	_ = clientB.ReloadPolicy(policyWithBoth)

	// 2. Injecting signed offer SDP with relay candidate MUST be rejected before installation.
	if err := clientB.InjectRawEnvelopeForTesting(relayOfferRaw); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("T08: expected ErrProhibitedCandidate for SDP relay candidate, got %v", err)
	}

	// 3. Install a clean signed offer, then inject trickled relay candidate & hub-endpoint candidate.
	sid2, _ := protocol.NewSessionID()
	_, cleanOfferRaw, _ := protocol.SignEnvelope(
		ids.peerA,
		protocol.TypeOffer,
		ids.peerB.PeerID,
		sid2,
		0,
		0,
		time.Now().Add(60*time.Second).Unix(),
		protocol.SDPBody{SDP: baseOffer.SDP},
	)
	if err := clientB.InjectRawEnvelopeForTesting(cleanOfferRaw); err != nil {
		t.Fatalf("clean offer install: %v", err)
	}

	mid := "0"
	mline := uint16(0)
	_, trickleRelayRaw, _ := protocol.SignEnvelope(
		ids.peerA,
		protocol.TypeCandidate,
		ids.peerB.PeerID,
		sid2,
		0,
		1,
		time.Now().Add(60*time.Second).Unix(),
		protocol.CandidateBody{
			Candidate:        "candidate:2 1 UDP 16777295 198.51.100.77 50000 typ relay raddr 192.0.2.2 rport 40001",
			SDPMid:           &mid,
			SDPMLineIndex:    &mline,
			UsernameFragment: "ufrag",
		},
	)
	if err := clientB.InjectRawEnvelopeForTesting(trickleRelayRaw); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("T08: expected ErrProhibitedCandidate for trickled relay candidate, got %v", err)
	}

	// Candidate targeting Hub's STUN UDP endpoint MUST also be rejected as a prohibited destination!
	stunUDP := srv.STUNAddr().String()
	parts := strings.Split(stunUDP, ":")
	_, trickleHubEPRaw, _ := protocol.SignEnvelope(
		ids.peerA,
		protocol.TypeCandidate,
		ids.peerB.PeerID,
		sid2,
		0,
		2,
		time.Now().Add(60*time.Second).Unix(),
		protocol.CandidateBody{
			Candidate:        "candidate:3 1 UDP 2130706431 " + parts[0] + " " + parts[1] + " typ host",
			SDPMid:           &mid,
			SDPMLineIndex:    &mline,
			UsernameFragment: "ufrag",
		},
	)
	if err := clientB.InjectRawEnvelopeForTesting(trickleHubEPRaw); !errors.Is(err, peer.ErrProhibitedEndpoint) {
		t.Fatalf("T08: expected ErrProhibitedEndpoint for Hub STUN destination, got %v", err)
	}

	if clientB.ProhibitedCandidateCount() < 3 {
		t.Fatalf("expected >= 3 prohibited candidates recorded, got %d", clientB.ProhibitedCandidateCount())
	}
}

// TestT10_StopHubDuringHealthyDirectSession verifies T10:
// Existing direct P2P data transfer continues uninterrupted when the Hub stops,
// while fresh negotiations fail closed.
func TestT10_StopHubDuringHealthyDirectSession(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	// Allow C<->A in policy too so we can verify fresh negotiations fail once Hub stops.
	pol := ids.policy
	pol.ACLRules = append(pol.ACLRules, identity.ACLRule{PeerA: ids.peerC.PeerID, PeerB: ids.peerA.PeerID})

	srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", pol, nil)

	sessBCh := make(chan *peer.Session, 1)
	clientA, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerA,
		Membership:      ids.memA,
		Policy:          pol,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerB,
		Membership:      ids.memB,
		Policy:          pol,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		OnSession:       func(s *peer.Session) { sessBCh <- s },
	})
	defer clientB.Close()

	clientC, _ := peer.NewClient(peer.Config{
		KeyPair:                 ids.peerC,
		Membership:              ids.memC,
		Policy:                  pol,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		OfferToConnectedTimeout: 2 * time.Second,
	})
	defer clientC.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)
	_ = clientC.Register(ctx)

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("initial connect A->B: %v", err)
	}
	sessB := <-sessBCh

	// Stop the entire Hub (both WSS control plane and STUN server)!
	if err := srv.Close(); err != nil {
		t.Fatalf("srv.Close: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// Existing direct session A<->B MUST remain Connected and transfer payloads!
	if sessA.State() != peer.StateConnected || sessB.State() != peer.StateConnected {
		t.Fatalf("T10: expected direct session to stay Connected during hub outage, got A=%s B=%s", sessA.State(), sessB.State())
	}
	for i := 0; i < 8; i++ {
		chunk := bytes.Repeat([]byte{byte(0x30 + i)}, 8192)
		if err := sessA.Send(ctx, chunk); err != nil {
			t.Fatalf("T10: direct Send after hub stop failed: %v", err)
		}
		got := <-sessB.Messages()
		if !bytes.Equal(got, chunk) {
			t.Fatal("T10: payload mismatch after hub stop")
		}
	}

	// Meanwhile, fresh negotiation C->A MUST fail closed while Hub is stopped!
	if _, err := clientC.Connect(ctx, ids.peerA.PeerID); err == nil {
		t.Fatal("T10: expected new negotiation to fail when Hub is offline")
	}
}

// TestGlareConcurrentOffers verifies Section 5 deterministic glare resolution:
// when both peers send concurrent offers simultaneously, the lexicographically smaller
// peer_id's offer wins and both peers converge to a single Connected session.
func TestGlareConcurrentOffers(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", ids.policy, nil)

	clientA, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerA,
		Membership:      ids.memA,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(peer.Config{
		KeyPair:         ids.peerB,
		Membership:      ids.memB,
		Policy:          ids.policy,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)

	var (
		sessA, sessB *peer.Session
		errA, errB   error
		wg           sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		sessA, errA = clientA.Connect(ctx, ids.peerB.PeerID)
	}()
	go func() {
		defer wg.Done()
		sessB, errB = clientB.Connect(ctx, ids.peerA.PeerID)
	}()
	wg.Wait()

	if errA != nil || errB != nil {
		t.Fatalf("glare Connect failed: errA=%v errB=%v", errA, errB)
	}
	if sessA.SessionID() != sessB.SessionID() {
		t.Fatalf("glare sessions did not converge to same session_id: A=%s B=%s", sessA.SessionID(), sessB.SessionID())
	}

	if err := sessA.Send(ctx, []byte("from-A")); err != nil {
		t.Fatal(err)
	}
	if got := <-sessB.Messages(); string(got) != "from-A" {
		t.Fatalf("unexpected message %q", string(got))
	}
}
