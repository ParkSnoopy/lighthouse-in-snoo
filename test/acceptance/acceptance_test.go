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

// TestArchitectureAndControlPlaneInvariants verifies dependency isolation, TLS 1.3 WSS
// enforcement, /healthz privacy, and zero-config stateless hub invariants.
func TestArchitectureAndControlPlaneInvariants(t *testing.T) {
	t.Parallel()

	outHub, err := exec.Command("go", "list", "-deps", "lighthouse-in-snoo/internal/hub").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps internal/hub failed: %v\n%s", err, string(outHub))
	}
	if strings.Contains(string(outHub), "github.com/pion/webrtc") {
		t.Fatalf("ARCH violation: hub control plane depends on pion/webrtc:\n%s", string(outHub))
	}
	outSTUN, err := exec.Command("go", "list", "-deps", "lighthouse-in-snoo/internal/stunserver").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps internal/stunserver failed: %v\n%s", err, string(outSTUN))
	}
	if strings.Contains(string(outSTUN), "github.com/pion/webrtc") || strings.Contains(string(outSTUN), "github.com/pion/turn") {
		t.Fatalf("ARCH violation: stunserver depends on pion/webrtc or pion/turn:\n%s", string(outSTUN))
	}
	outHubCmd, err := exec.Command("go", "list", "-deps", "lighthouse-in-snoo/cmd/lighthouse").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps cmd/lighthouse failed: %v\n%s", err, string(outHubCmd))
	}
	if strings.Contains(string(outHubCmd), "fyne.io/fyne") || strings.Contains(string(outHubCmd), "modernc.org/sqlite") {
		t.Fatalf("ARCH violation: static hub binary depends on fyne or sqlite:\n%s", string(outHubCmd))
	}

	srv, pki, _, wsURL, _ := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

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
	_, pki, hubLogs, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	peerLogs := &safeLogBuffer{}
	peerLogger := slog.New(slog.NewJSONHandler(peerLogs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sessBCh := make(chan *peer.Session, 1)
	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:             ids.peerA,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		STUNServerURI:       stunURI,
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Consent:             allowAllConsent(),
		Logger:              peerLogger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:             ids.peerB,
		SignalingURL:        wsURL,
		TLSConfig:           pki.clientTLS,
		STUNServerURI:       stunURI,
		NetworkTypes:        []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback:     true,
		EnablePacketChannel: true,
		Consent:             allowAllConsent(),
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
	if mapped, err := clientA.ProbeSTUNS(ctx); err != nil || mapped == nil {
		t.Fatalf("ProbeSTUNS DTLS 1.3 / UDP failed: mapped=%v err=%v", mapped, err)
	}
	authorizeOnPassphrase(t, ctx, "t01-room", clientB, clientA)

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

	oversized := make([]byte, peer.MaxApplicationMessageBytes+1)
	if err := sessA.Send(ctx, oversized); !errors.Is(err, peer.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge for 16KiB+1 payload, got %v", err)
	}

	combinedLogs := hubLogs.String() + "\n" + peerLogs.String()
	for _, forbidden := range []string{"v=0\r\n", "a=ice-pwd:", string(secretPayload), "typ host"} {
		if strings.Contains(combinedLogs, forbidden) {
			t.Fatalf("log privacy violation: found %q in logs:\n%s", forbidden, combinedLogs)
		}
	}

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
			_, pki, _, wsURL, stunURI := startTestHub(t, fam.tcpNet, fam.bindHost, fam.stunAddr, nil)

			sessBCh := make(chan *peer.Session, 1)
			clientA, err := peer.NewClient(&peer.Config{
				KeyPair:         ids.peerA,
				SignalingURL:    wsURL,
				TLSConfig:       pki.clientTLS,
				STUNServerURI:   stunURI,
				NetworkTypes:    []webrtc.NetworkType{fam.netType},
				IncludeLoopback: true,
				Consent:         allowAllConsent(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clientA.Close()

			clientB, err := peer.NewClient(&peer.Config{
				KeyPair:         ids.peerB,
				SignalingURL:    wsURL,
				TLSConfig:       pki.clientTLS,
				STUNServerURI:   stunURI,
				NetworkTypes:    []webrtc.NetworkType{fam.netType},
				IncludeLoopback: true,
				Consent:         allowAllConsent(),
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
			authorizeOnPassphrase(t, ctx, "t02-"+fam.name, clientB, clientA)

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
	_, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	payloadDelivered := make(chan []byte, 1)

	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:                 ids.peerA,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		Consent:                 allowAllConsent(),
		OfferToConnectedTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:                 ids.peerB,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		Consent:                 allowAllConsent(),
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
	authorizeOnPassphrase(t, ctx, "t05-room", clientB, clientA)

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
			srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)
			srv.SetForwardTamperHookForTesting(tc.mutate)

			clientA, _ := peer.NewClient(&peer.Config{
				KeyPair:                 ids.peerA,
				SignalingURL:            wsURL,
				TLSConfig:               pki.clientTLS,
				STUNServerURI:           stunURI,
				IncludeLoopback:         true,
				Consent:                 allowAllConsent(),
				OfferToConnectedTimeout: 1200 * time.Millisecond,
			})
			defer clientA.Close()

			clientB, _ := peer.NewClient(&peer.Config{
				KeyPair:                 ids.peerB,
				SignalingURL:            wsURL,
				TLSConfig:               pki.clientTLS,
				STUNServerURI:           stunURI,
				IncludeLoopback:         true,
				Consent:                 allowAllConsent(),
				OfferToConnectedTimeout: 1200 * time.Millisecond,
			})
			defer clientB.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = clientA.Register(ctx)
			_ = clientB.Register(ctx)
			authorizeOnPassphrase(t, ctx, "t06-room", clientB, clientA)

			if _, err := clientA.Connect(ctx, ids.peerB.PeerID); err == nil {
				t.Fatalf("T06 (%s): expected tampered signaling to fail", tc.name)
			}
			if clientB.RejectedSignalCount() == 0 {
				t.Fatalf("T06 (%s): expected Peer B to record rejected tampered envelope", tc.name)
			}
		})
	}
}

// TestT07_DeniedBlacklistedAndReplayedSignalingRejected verifies T07:
// Default fail-closed consent, explicit user Deny/Blacklist, and signaling replay rejection.
func TestT07_DeniedBlacklistedAndReplayedSignalingRejected(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Default fail-closed: nil ConsentHandler MUST deny incoming offers.
	clientDefaultDeny, err := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerB,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientDefaultDeny.Close()
	if err := clientDefaultDeny.Register(ctx); err != nil {
		t.Fatal(err)
	}

	clientC, err := peer.NewClient(&peer.Config{
		KeyPair:                 ids.peerC,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		OfferToConnectedTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientC.Close()
	if err := clientC.Register(ctx); err != nil {
		t.Fatal(err)
	}

	// 0. Server auto-ACL rejects C -> B before B enables broadcast on a shared passphrase.
	if _, err := clientC.Connect(ctx, ids.peerB.PeerID); !errors.Is(err, peer.ErrNotAuthorized) {
		t.Fatalf("T07: expected ErrNotAuthorized before broadcast, got %v", err)
	}

	authorizeOnPassphrase(t, ctx, "t07-room", clientDefaultDeny, clientC)

	if _, err := clientC.Connect(ctx, ids.peerB.PeerID); !errors.Is(err, peer.ErrUserDenied) {
		t.Fatalf("T07: expected ErrUserDenied on nil Consent handler, got %v", err)
	}

	// 2. Explicit blacklist on Peer B rejects future offers from Peer C with ErrPeerBlacklisted.
	if err := clientDefaultDeny.Blacklist(ids.peerC.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := clientC.Connect(ctx, ids.peerB.PeerID); !errors.Is(err, peer.ErrPeerBlacklisted) {
		t.Fatalf("T07: expected ErrPeerBlacklisted for blacklisted peer, got %v", err)
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
		V:         protocol.Version,
		Type:      protocol.TypeRegister,
		PeerID:    ids.peerA.PeerID,
		PublicKey: identity.EncodePublicKey(ids.peerA.PublicKey),
		HubOrigin: srv.HubOrigin(),
		Challenge: chal.Challenge,
		Proof:     proof,
	})
	_ = wsA.Write(ctx, websocket.MessageText, regRaw)
	_, _, _ = wsA.Read(ctx) // registered
	t07Keys, _ := identity.DeriveChannelKeys("t07-room")
	joinRaw, _ := json.Marshal(protocol.ChannelJoinMessage{V: protocol.Version, Type: protocol.TypeChannelJoin, ChannelID: t07Keys.ChannelID})
	_ = wsA.Write(ctx, websocket.MessageText, joinRaw)
	_, _, _ = wsA.Read(ctx) // channel_peers snapshot confirming auto-ACL membership

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

	if err := clientDefaultDeny.InjectRawEnvelopeForTesting(closeEnvRaw); !errors.Is(err, peer.ErrReplayedSignaling) {
		t.Fatalf("T07: expected Peer B ErrReplayedSignaling, got %v", err)
	}
}

// TestT08_RelayAndHubEndpointCandidatesRejected verifies T08:
// Plaintext ICE URIs, relay candidates when relay is disabled, and Hub endpoint candidates
// are all rejected before WebRTC installation.
func TestT08_RelayAndHubEndpointCandidatesRejected(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	for _, badURI := range []string{"stun:127.0.0.1:3478", "turn:127.0.0.1:3478"} {
		if _, err := peer.NewClient(&peer.Config{
			KeyPair:       ids.peerA,
			SignalingURL:  wsURL,
			STUNServerURI: badURI,
		}); !errors.Is(err, peer.ErrInsecureICEProhibited) || !errors.Is(err, peer.ErrInvalidICEConfig) {
			t.Fatalf("T08: expected ErrInsecureICEProhibited for %q, got %v", badURI, err)
		}
	}
	if _, err := peer.NewClient(&peer.Config{
		KeyPair:       ids.peerA,
		SignalingURL:  wsURL,
		TURNServerURI: "turns:127.0.0.1:5349",
	}); !errors.Is(err, peer.ErrInvalidICEConfig) {
		t.Fatalf("T08: expected ErrInvalidICEConfig for turns: without credentials, got %v", err)
	}

	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerA,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerB,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
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
	authorizeOnPassphrase(t, ctx, "t08-room", clientA, clientB)

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

	if err := clientB.InjectRawEnvelopeForTesting(relayOfferRaw); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("T08: expected ErrProhibitedCandidate for SDP relay candidate, got %v", err)
	}

	// Install clean signed offer, wait for async consent handler to promote it, then test trickled candidates.
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
	// Allow async consent goroutine to complete Offer installation.
	time.Sleep(150 * time.Millisecond)

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
	srv, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	sessBCh := make(chan *peer.Session, 1)
	clientA, _ := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerA,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerB,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
		OnSession:       func(s *peer.Session) { sessBCh <- s },
	})
	defer clientB.Close()

	clientC, _ := peer.NewClient(&peer.Config{
		KeyPair:                 ids.peerC,
		SignalingURL:            wsURL,
		TLSConfig:               pki.clientTLS,
		STUNServerURI:           stunURI,
		IncludeLoopback:         true,
		Consent:                 allowAllConsent(),
		OfferToConnectedTimeout: 2 * time.Second,
	})
	defer clientC.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)
	_ = clientC.Register(ctx)
	authorizeOnPassphrase(t, ctx, "t10-room", clientB, clientA)

	sessA, err := clientA.Connect(ctx, ids.peerB.PeerID)
	if err != nil {
		t.Fatalf("initial connect A->B: %v", err)
	}
	sessB := <-sessBCh

	if err := srv.Close(); err != nil {
		t.Fatalf("srv.Close: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

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

	if _, err := clientC.Connect(ctx, ids.peerA.PeerID); err == nil {
		t.Fatal("T10: expected new negotiation to fail when Hub is offline")
	}
}

// TestGlareConcurrentOffers verifies deterministic glare resolution:
// when both peers initiate concurrent offers, both converge to a single Connected session.
func TestGlareConcurrentOffers(t *testing.T) {
	t.Parallel()

	ids := newTestMeshIdentities(t)
	_, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	clientA, _ := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerA,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
	})
	defer clientA.Close()

	clientB, _ := peer.NewClient(&peer.Config{
		KeyPair:         ids.peerB,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
	})
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = clientA.Register(ctx)
	_ = clientB.Register(ctx)
	authorizeOnPassphrase(t, ctx, "glare-room", clientB, clientA)
	authorizeOnPassphrase(t, ctx, "glare-room", clientA, clientB)

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

// TestMixedAlgorithmDirectP2PConnectivity verifies that non-Ed25519 keys
// (NIST P-384 Peer A, RSA-2048 Peer B) interoperate end to end over DTLS 1.3.
func TestMixedAlgorithmDirectP2PConnectivity(t *testing.T) {
	t.Parallel()

	peerA, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{Algorithm: identity.AlgorithmNISTP384})
	if err != nil {
		t.Fatal(err)
	}
	peerB, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{Algorithm: identity.AlgorithmRSA, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}

	_, pki, _, wsURL, stunURI := startTestHub(t, "tcp4", "127.0.0.1:0", "127.0.0.1:0", nil)

	sessBCh := make(chan *peer.Session, 1)
	clientA, err := peer.NewClient(&peer.Config{
		KeyPair:         peerA,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		NetworkTypes:    []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := peer.NewClient(&peer.Config{
		KeyPair:         peerB,
		SignalingURL:    wsURL,
		TLSConfig:       pki.clientTLS,
		STUNServerURI:   stunURI,
		NetworkTypes:    []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
		IncludeLoopback: true,
		Consent:         allowAllConsent(),
		OnSession:       func(s *peer.Session) { sessBCh <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := clientA.Register(ctx); err != nil {
		t.Fatalf("Register P-384 A: %v", err)
	}
	if err := clientB.Register(ctx); err != nil {
		t.Fatalf("Register RSA-2048 B: %v", err)
	}
	authorizeOnPassphrase(t, ctx, "mixed-algo-room", clientB, clientA)

	sessA, err := clientA.Connect(ctx, peerB.PeerID)
	if err != nil {
		t.Fatalf("Connect P-384 -> RSA-2048: %v", err)
	}
	sessB := <-sessBCh

	if diag := sessA.Diagnostics(); diag.DTLSVersion != peer.ExpectedDTLS13HexVersion {
		t.Fatalf("expected DTLS 1.3, got %q", diag.DTLSVersion)
	}
	if err := sessA.Send(ctx, []byte("mixed-algo-ok")); err != nil {
		t.Fatal(err)
	}
	if got := <-sessB.Messages(); string(got) != "mixed-algo-ok" {
		t.Fatalf("payload mismatch: %q", string(got))
	}
}
