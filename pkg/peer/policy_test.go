package peer_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/protocol"
)

func TestSDPAndCandidatePolicyValidation(t *testing.T) {
	t.Parallel()

	// Reject TURN, turns, stuns, and TCP STUN URIs.
	for _, badURI := range []string{
		"turn:hub.example.com:3478",
		"turns:hub.example.com:5349",
		"stuns:hub.example.com:5349",
		"stun:hub.example.com:3478?transport=tcp",
	} {
		if err := peer.ValidateSTUNServerURI(badURI); !errors.Is(err, peer.ErrInvalidICEConfig) {
			t.Fatalf("expected ErrInvalidICEConfig for %q, got %v", badURI, err)
		}
	}
	if err := peer.ValidateSTUNServerURI("stun:hub.example.com:3478"); err != nil {
		t.Fatalf("valid stun URI rejected: %v", err)
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

	hubEP := []net.UDPAddr{{IP: net.ParseIP("203.0.113.10"), Port: 3478}}
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

	// Accept IPv6 link-local selected pair with interface zone suffix.
	zonedPair := &webrtc.ICECandidatePair{
		Local:  &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolUDP, Typ: webrtc.ICECandidateTypeHost, Address: "fe80::1%eth0", Port: 51000},
		Remote: &webrtc.ICECandidate{Protocol: webrtc.ICEProtocolUDP, Typ: webrtc.ICECandidateTypeHost, Address: "fe80::2%eth0", Port: 52000},
	}
	if err := peer.ValidateSelectedPair(zonedPair, hubEP, hubIP); err != nil {
		t.Fatalf("expected IPv6 link-local zoned pair to be allowed, got %v", err)
	}
}
