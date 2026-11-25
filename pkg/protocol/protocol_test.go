package protocol_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/protocol"
)

func TestSignedEnvelopeLifecycleAndTamperDetection(t *testing.T) {
	t.Parallel()

	peerA, _ := identity.GenerateKeyPair()
	peerB, _ := identity.GenerateKeyPair()
	sid, err := protocol.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_795_560_000, 0)
	mid := "0"
	mline := uint16(0)
	_, raw, err := protocol.SignEnvelope(
		peerA,
		protocol.TypeCandidate,
		peerB.PeerID,
		sid,
		0,
		2,
		now.Add(60*time.Second).Unix(),
		protocol.CandidateBody{
			Candidate:        "candidate:1 1 UDP 2130706431 192.0.2.10 50000 typ host",
			SDPMid:           &mid,
			SDPMLineIndex:    &mline,
			UsernameFragment: "abcd",
		},
	)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	parsed, err := protocol.ParseUnsignedEnvelope(raw, protocol.MaxSignalingMessageSize)
	if err != nil {
		t.Fatalf("ParseUnsignedEnvelope: %v", err)
	}
	if err := protocol.VerifyEnvelopeSignature(parsed, peerA.PublicKey, now, 60*time.Second, 30*time.Second); err != nil {
		t.Fatalf("VerifyEnvelopeSignature: %v", err)
	}

	// Tamper with candidate port in raw JSON -> signature verification MUST fail.
	tampered := bytes.Replace(raw, []byte("50000"), []byte("50001"), 1)
	tamperedEnv, err := protocol.ParseUnsignedEnvelope(tampered, protocol.MaxSignalingMessageSize)
	if err != nil {
		t.Fatalf("ParseUnsignedEnvelope tampered: %v", err)
	}
	if err := protocol.VerifyEnvelopeSignature(tamperedEnv, peerA.PublicKey, now, 60*time.Second, 30*time.Second); !errors.Is(err, protocol.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered body, got %v", err)
	}

	// Expired message outside 30s skew MUST fail.
	if err := protocol.VerifyEnvelopeSignature(parsed, peerA.PublicKey, now.Add(95*time.Second), 60*time.Second, 30*time.Second); !errors.Is(err, protocol.ErrExpiredEnvelope) {
		t.Fatalf("expected ErrExpiredEnvelope, got %v", err)
	}
}

func TestHeaderRejectsUnknownTypesVersionsAndOversizedMessages(t *testing.T) {
	t.Parallel()

	if _, err := protocol.PeekHeader([]byte(`{"v":2,"type":"heartbeat"}`), 1024); !errors.Is(err, protocol.ErrUnsupportedVer) {
		t.Fatalf("expected ErrUnsupportedVer, got %v", err)
	}
	if _, err := protocol.PeekHeader([]byte(`{"v":1,"type":"tunnel_data"}`), 1024); !errors.Is(err, protocol.ErrUnknownType) {
		t.Fatalf("expected ErrUnknownType, got %v", err)
	}
	huge := `{"v":1,"type":"heartbeat","pad":"` + strings.Repeat("x", 70000) + `"}`
	if _, err := protocol.PeekHeader([]byte(huge), protocol.MaxSignalingMessageSize); !errors.Is(err, protocol.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
}
