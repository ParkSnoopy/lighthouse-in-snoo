package peer_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/pion/stun/v5"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/protocol"
)

func TestSDPAndCandidatePolicyValidation(t *testing.T) {
	t.Parallel()

	// By default (allowInsecure=false), plaintext stun: and turn: MUST be rejected.
	for _, insecureURI := range []string{
		"stun:hub.example.com:3478",
		"turn:hub.example.com:3478",
		"turn:hub.example.com:3478?transport=udp",
		"turn:hub.example.com:3478?transport=tcp",
	} {
		if err := peer.ValidateSTUNServerURI(insecureURI); !errors.Is(err, peer.ErrInsecureICEProhibited) || !errors.Is(err, peer.ErrInvalidICEConfig) {
			t.Fatalf("expected ErrInsecureICEProhibited for %q, got %v", insecureURI, err)
		}
		if _, err := peer.ValidateICEServerURI(insecureURI, true); err != nil {
			t.Fatalf("expected %q to succeed with allowInsecure=true, got %v", insecureURI, err)
		}
	}

	// Secure stuns: and turns: are permitted by default and prioritize UDP (DTLS/UDP) over TCP.
	for _, tc := range []struct {
		uri       string
		wantProto stun.ProtoType
		wantPort  int
	}{
		{"stuns:hub.example.com", stun.ProtoTypeUDP, 5349},
		{"stuns:hub.example.com:5349", stun.ProtoTypeUDP, 5349},
		{"stuns:hub.example.com:5349?transport=udp", stun.ProtoTypeUDP, 5349},
		{"turns:hub.example.com", stun.ProtoTypeUDP, 5349},
		{"turns:hub.example.com:5349", stun.ProtoTypeUDP, 5349},
		{"turns:hub.example.com:5349?transport=udp", stun.ProtoTypeUDP, 5349},
		{"turns:hub.example.com:5349?transport=tcp", stun.ProtoTypeTCP, 5349},
	} {
		parsed, err := peer.ValidateICEServerURI(tc.uri, false)
		if err != nil {
			t.Fatalf("valid secure URI %q rejected: %v", tc.uri, err)
		}
		if parsed.Proto != tc.wantProto || parsed.Port != tc.wantPort {
			t.Fatalf("URI %q -> proto=%s port=%d; want proto=%s port=%d", tc.uri, parsed.Proto, parsed.Port, tc.wantProto, tc.wantPort)
		}
	}

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, _ = pc.CreateDataChannel("data/v1", nil)
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}

	hubEP := []net.UDPAddr{{IP: net.ParseIP("203.0.113.10"), Port: 5349}}
	hubIP := []net.IP{net.ParseIP("203.0.113.10")}

	info, err := peer.ValidateAndInspectRemoteSDP(offer.SDP, hubEP, hubIP)
	if err != nil {
		t.Fatalf("valid data-only SDP rejected: %v", err)
	}
	if len(info.SHA256Fingerprints) == 0 {
		t.Fatal("expected extracted sha-256 fingerprint")
	}

	// Reject audio/video media SDP (profile is data-channel-only).
	audioSDP := strings.Replace(offer.SDP, "m=application ", "m=audio ", 1)
	if _, err := peer.ValidateAndInspectRemoteSDP(audioSDP, hubEP, hubIP); !errors.Is(err, peer.ErrInvalidRemoteSDP) {
		t.Fatalf("expected ErrInvalidRemoteSDP for audio media, got %v", err)
	}

	// Reject ice-lite SDP.
	iceLiteSDP := offer.SDP + "a=ice-lite\r\n"
	if _, err := peer.ValidateAndInspectRemoteSDP(iceLiteSDP, hubEP, hubIP); !errors.Is(err, peer.ErrInvalidRemoteSDP) {
		t.Fatalf("expected ErrInvalidRemoteSDP for ice-lite, got %v", err)
	}

	// Reject TCP candidate and Hub IP candidate in Trickle ICE.
	if err := peer.ValidateTrickleCandidate(protocol.CandidateBody{
		Candidate: "candidate:1 1 TCP 2105524479 192.0.2.10 9 typ host tcptype active",
	}, hubEP, hubIP); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("expected ErrProhibitedCandidate for TCP candidate, got %v", err)
	}
	if err := peer.ValidateTrickleCandidate(protocol.CandidateBody{
		Candidate: "candidate:1 1 UDP 2130706431 203.0.113.10 50000 typ host",
	}, hubEP, hubIP); !errors.Is(err, peer.ErrProhibitedEndpoint) {
		t.Fatalf("expected ErrProhibitedEndpoint for Hub IP candidate, got %v", err)
	}

	// Relay candidates are rejected in direct-only mode and allowed when TURNS/TURN is enabled.
	relayCand := protocol.CandidateBody{
		Candidate: "candidate:2 1 UDP 16777295 198.51.100.77 50000 typ relay raddr 192.0.2.2 rport 40001",
	}
	if err := peer.ValidateTrickleCandidateWithPolicy(relayCand, hubEP, hubIP, false); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("expected ErrProhibitedCandidate for relay when allowRelay=false, got %v", err)
	}
	if err := peer.ValidateTrickleCandidateWithPolicy(relayCand, hubEP, nil, true); err != nil {
		t.Fatalf("expected UDP relay candidate allowed when allowRelay=true, got %v", err)
	}

	// Accept IPv6 link-local selected pair with interface zone suffix.
	zonedPair := &webrtc.ICECandidatePair{
		Local:  &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolUDP, Typ: webrtc.ICECandidateTypeHost, Address: "fe80::1%eth0", Port: 51000},
		Remote: &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolUDP, Typ: webrtc.ICECandidateTypeHost, Address: "fe80::2%eth0", Port: 52000},
	}
	if err := peer.ValidateSelectedPair(zonedPair, hubEP, hubIP); err != nil {
		t.Fatalf("expected IPv6 link-local zoned pair to be allowed, got %v", err)
	}
}

func TestTCPOnlyPolicyValidation(t *testing.T) {
	t.Parallel()

	// In TCP-only mode, stuns:/turns: default to TCP and ?transport=udp is rejected.
	for _, tc := range []struct {
		uri           string
		allowInsecure bool
		wantErr       error
		wantProto     stun.ProtoType
	}{
		{"stuns:hub.example.com:5349", false, nil, stun.ProtoTypeTCP},
		{"stuns:hub.example.com:5349?transport=tcp", false, nil, stun.ProtoTypeTCP},
		{"turns:hub.example.com:5349", false, nil, stun.ProtoTypeTCP},
		{"stuns:hub.example.com:5349?transport=udp", false, peer.ErrInvalidICEConfig, 0},
		{"turns:hub.example.com:5349?transport=udp", false, peer.ErrInvalidICEConfig, 0},
		{"stun:hub.example.com:3478", false, peer.ErrInsecureICEProhibited, 0},
		{"stun:hub.example.com:3478", true, nil, stun.ProtoTypeTCP},
	} {
		parsed, err := peer.ValidateICEServerURIWithMode(tc.uri, tc.allowInsecure, true)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("URI %q (tcpOnly=true): got err=%v, want %v", tc.uri, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("URI %q (tcpOnly=true): unexpected err=%v", tc.uri, err)
		}
		if parsed.Proto != tc.wantProto {
			t.Fatalf("URI %q (tcpOnly=true): proto=%s, want %s", tc.uri, parsed.Proto, tc.wantProto)
		}
	}

	hubEP := []net.UDPAddr{{IP: net.ParseIP("203.0.113.10"), Port: 5349}}
	hubIP := []net.IP{net.ParseIP("203.0.113.10")}
	tcpPolicy := peer.CandidatePolicy{TCPOnly: true}

	// TCP host candidates (passive & active) are allowed in TCP-only mode.
	for _, cand := range []string{
		"candidate:1 1 TCP 2105524479 192.0.2.10 9 typ host tcptype active",
		"candidate:2 1 TCP 2105524478 192.0.2.10 42000 typ host tcptype passive",
	} {
		if err := peer.ValidateTrickleCandidateWithCandidatePolicy(protocol.CandidateBody{Candidate: cand}, hubEP, hubIP, tcpPolicy); err != nil {
			t.Fatalf("expected TCP candidate allowed in TCP-only mode, got %v", err)
		}
	}

	// UDP candidates and hub TCP endpoints MUST be rejected in TCP-only mode.
	if err := peer.ValidateTrickleCandidateWithCandidatePolicy(protocol.CandidateBody{
		Candidate: "candidate:3 1 UDP 2130706431 192.0.2.10 50000 typ host",
	}, hubEP, hubIP, tcpPolicy); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("expected ErrProhibitedCandidate for UDP candidate in TCP-only mode, got %v", err)
	}
	if err := peer.ValidateTrickleCandidateWithCandidatePolicy(protocol.CandidateBody{
		Candidate: "candidate:4 1 TCP 2105524478 203.0.113.10 5349 typ host tcptype passive",
	}, hubEP, nil, tcpPolicy); !errors.Is(err, peer.ErrProhibitedEndpoint) {
		t.Fatalf("expected ErrProhibitedEndpoint for hub TCP endpoint, got %v", err)
	}

	// Selected pair validation enforces TCP-TCP in TCP-only mode and rejects UDP pairs.
	tcpPair := &webrtc.ICECandidatePair{
		Local:  &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolTCP, Typ: webrtc.ICECandidateTypeHost, Address: "192.0.2.1", Port: 41000},
		Remote: &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolTCP, Typ: webrtc.ICECandidateTypeHost, Address: "192.0.2.2", Port: 42000},
	}
	if err := peer.ValidateSelectedPairWithCandidatePolicy(tcpPair, hubEP, hubIP, tcpPolicy); err != nil {
		t.Fatalf("expected TCP pair allowed in TCP-only mode, got %v", err)
	}
	udpPair := &webrtc.ICECandidatePair{
		Local:  &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolUDP, Typ: webrtc.ICECandidateTypeHost, Address: "192.0.2.1", Port: 41000},
		Remote: &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolUDP, Typ: webrtc.ICECandidateTypeHost, Address: "192.0.2.2", Port: 42000},
	}
	if err := peer.ValidateSelectedPairWithCandidatePolicy(udpPair, hubEP, hubIP, tcpPolicy); !errors.Is(err, peer.ErrProhibitedCandidate) {
		t.Fatalf("expected ErrProhibitedCandidate for UDP selected pair in TCP-only mode, got %v", err)
	}
}
