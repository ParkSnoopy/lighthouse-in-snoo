package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/pkg/identity"
)

const (
	// Version is the control-plane protocol version (Section 4.3).
	Version = 1

	// DomainSignalV1 is the ASCII domain separator followed by one zero byte (Section 4.3).
	DomainSignalV1 = "LIGHTHOUSE-SIGNAL-V1\x00"

	// MaxSignalingMessageSize is the default maximum control-plane JSON size (64 KiB, Section 9).
	MaxSignalingMessageSize = 64 * 1024

	// DefaultSignalingTTL is the default signaling message lifetime (60 s, Section 9).
	DefaultSignalingTTL = 60 * time.Second

	// DefaultMaxClockSkew is the maximum tolerated clock skew (30 s, Section 9).
	DefaultMaxClockSkew = 30 * time.Second

	// DefaultMaxCandidatesPerGeneration bounds trickled candidates per sender/generation (Section 9).
	DefaultMaxCandidatesPerGeneration = 128

	// ChallengeBytes is the minimum single-use registration challenge length (32 bytes, Section 3).
	ChallengeBytes = 32

	// ChallengeTTL is the registration challenge lifetime (60 s, Section 3).
	ChallengeTTL = 60 * time.Second

	// SessionIDBytes is 128 bits (16 bytes, Section 4.3).
	SessionIDBytes = 16
	// SessionIDEncodedLen is the base64url unpadded length of 16 bytes.
	SessionIDEncodedLen = 22
)

// Control-plane message types (Section 4.2).
const (
	TypeChallenge       = "challenge"
	TypeRegister        = "register"
	TypeRegistered      = "registered"
	TypeHeartbeat       = "heartbeat"
	TypeLookup          = "lookup"
	TypeLookupResult    = "lookup_result"
	TypeOffer           = "offer"
	TypeAnswer          = "answer"
	TypeCandidate       = "candidate"
	TypeEndOfCandidates = "end_of_candidates"
	TypeClose           = "close"
	TypeError           = "error"
)

// Machine-readable failure codes (Section 4.2).
const (
	ErrCodeMalformedMessage   = "malformed_message"
	ErrCodeMessageTooLarge    = "message_too_large"
	ErrCodeUnsupportedVersion = "unsupported_version"
	ErrCodeUnknownType        = "unknown_type"
	ErrCodeUnauthenticated    = "unauthenticated"
	ErrCodeChallengeInvalid   = "challenge_invalid"
	ErrCodeAuthFailed         = "auth_failed"
	ErrCodeUnknownPeer        = "unknown_peer"
	ErrCodeUnauthorizedPair   = "unauthorized_pair"
	ErrCodePeerOffline        = "peer_offline"
	ErrCodeSenderMismatch     = "sender_mismatch"
	ErrCodeInvalidSignature   = "invalid_signature"
	ErrCodeExpiredMessage     = "expired_message"
	ErrCodeReplayedSignaling  = "replayed_signaling"
	ErrCodeStaleGeneration    = "stale_generation"
	ErrCodeCandidateLimit     = "candidate_limit_exceeded"
	ErrCodeRateLimited        = "rate_limited"
	ErrCodeSessionLimit       = "session_limit_exceeded"
)

var (
	ErrMessageTooLarge  = errors.New("protocol: message exceeds size limit")
	ErrUnsupportedVer   = errors.New("protocol: unsupported protocol version")
	ErrUnknownType      = errors.New("protocol: unknown message type")
	ErrInvalidEnvelope  = errors.New("protocol: invalid signaling envelope")
	ErrInvalidSessionID = errors.New("protocol: invalid 128-bit session_id")
	ErrExpiredEnvelope  = errors.New("protocol: signaling message expired or outside clock skew")
	ErrInvalidSignature = errors.New("protocol: invalid Ed25519 envelope signature")
	ErrInvalidBody      = errors.New("protocol: invalid message body")
)

// BaseHeader inspects the version and type of an incoming JSON control-plane message.
type BaseHeader struct {
	V    int    `json:"v"`
	Type string `json:"type"`
}

// PeekHeader validates UTF-8, duplicate keys, size bounds, version, and known message type.
func PeekHeader(raw []byte, maxBytes int) (BaseHeader, error) {
	if maxBytes <= 0 {
		maxBytes = MaxSignalingMessageSize
	}
	if len(raw) == 0 {
		return BaseHeader{}, jcs.ErrInvalidJSON
	}
	if len(raw) > maxBytes {
		return BaseHeader{}, ErrMessageTooLarge
	}
	val, err := jcs.ParseStrict(raw)
	if err != nil {
		return BaseHeader{}, err
	}
	// Extract only "v" and "type" from top-level object after strict parse.
	var partial struct {
		V    *int    `json:"v"`
		Type *string `json:"type"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return BaseHeader{}, jcs.ErrInvalidJSON
	}
	// Ensure top-level JSON value is an object.
	if _, isSlice := val.([]any); isSlice || partial.V == nil || partial.Type == nil {
		return BaseHeader{}, jcs.ErrInvalidJSON
	}
	if *partial.V != Version {
		return BaseHeader{}, ErrUnsupportedVer
	}
	if !IsKnownType(*partial.Type) {
		return BaseHeader{}, ErrUnknownType
	}
	return BaseHeader{V: *partial.V, Type: *partial.Type}, nil
}

// IsKnownType reports whether msgType is one of the 12 specification-defined types.
func IsKnownType(msgType string) bool {
	switch msgType {
	case TypeChallenge, TypeRegister, TypeRegistered, TypeHeartbeat,
		TypeLookup, TypeLookupResult, TypeOffer, TypeAnswer,
		TypeCandidate, TypeEndOfCandidates, TypeClose, TypeError:
		return true
	default:
		return false
	}
}

// IsPeerSignalType reports whether msgType is a signed peer-to-peer signaling envelope.
func IsPeerSignalType(msgType string) bool {
	switch msgType {
	case TypeOffer, TypeAnswer, TypeCandidate, TypeEndOfCandidates, TypeClose:
		return true
	default:
		return false
	}
}

// ChallengeMessage is sent by Hub -> Peer upon WSS connection (Section 3 & 4.2).
type ChallengeMessage struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	HubOrigin string `json:"hub_origin"`
	ExpiresAt int64  `json:"expires_at"`
}

// RegisterMessage is sent by Peer -> Hub to authenticate and register presence (Section 3 & 4.2).
type RegisterMessage struct {
	V          int                        `json:"v"`
	Type       string                     `json:"type"`
	PeerID     string                     `json:"peer_id"`
	PublicKey  string                     `json:"public_key"`
	HubOrigin  string                     `json:"hub_origin"`
	Challenge  string                     `json:"challenge"`
	Membership *identity.MembershipRecord `json:"membership,omitempty"`
	Proof      string                     `json:"proof"`
}

// RegisteredMessage is sent by Hub -> Peer on successful registration (Section 4.2).
type RegisteredMessage struct {
	V                    int    `json:"v"`
	Type                 string `json:"type"`
	PeerID               string `json:"peer_id"`
	ExpiresAt            int64  `json:"expires_at"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
}

// HeartbeatMessage refreshes an authenticated peer's presence lease (Section 4.2).
type HeartbeatMessage struct {
	V    int    `json:"v"`
	Type string `json:"type"`
}

// LookupMessage requests target peer presence and identity material (Section 4.2).
type LookupMessage struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	Target string `json:"target"`
}

// LookupResultMessage returns authorized target availability and identity (Section 4.2).
type LookupResultMessage struct {
	V          int                        `json:"v"`
	Type       string                     `json:"type"`
	Target     string                     `json:"target"`
	Online     bool                       `json:"online"`
	PublicKey  string                     `json:"public_key,omitempty"`
	Membership *identity.MembershipRecord `json:"membership,omitempty"`
}

// ErrorMessage delivers bounded, machine-readable failure codes from Hub -> Peer (Section 4.2).
type ErrorMessage struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

// SignalEnvelope is the signed peer-to-peer signaling envelope (Section 4.3).
type SignalEnvelope struct {
	V          int             `json:"v"`
	Type       string          `json:"type"`
	From       string          `json:"from"`
	To         string          `json:"to"`
	SessionID  string          `json:"session_id"`
	Generation uint32          `json:"generation"`
	Seq        uint64          `json:"seq"`
	ExpiresAt  int64           `json:"expires_at"`
	Body       json.RawMessage `json:"body"`
	Sig        string          `json:"sig"`
}

type unsignedSignalEnvelope struct {
	V          int             `json:"v"`
	Type       string          `json:"type"`
	From       string          `json:"from"`
	To         string          `json:"to"`
	SessionID  string          `json:"session_id"`
	Generation uint32          `json:"generation"`
	Seq        uint64          `json:"seq"`
	ExpiresAt  int64           `json:"expires_at"`
	Body       json.RawMessage `json:"body"`
}

// SDPBody is the body of signed "offer" and "answer" envelopes.
type SDPBody struct {
	SDP string `json:"sdp"`
}

// CandidateBody is the body of signed "candidate" envelopes (Section 4.3).
type CandidateBody struct {
	Candidate        string  `json:"candidate"`
	SDPMid           *string `json:"sdpMid,omitempty"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex,omitempty"`
	UsernameFragment string  `json:"usernameFragment,omitempty"`
}

// EndOfCandidatesBody is the body of signed "end_of_candidates" envelopes (Section 4.3).
type EndOfCandidatesBody struct {
	UsernameFragment string `json:"usernameFragment"`
}

// CloseBody is the body of signed "close" envelopes (Section 4.3).
type CloseBody struct {
	Reason string `json:"reason"`
}

// NewSessionID generates a cryptographically random 128-bit value encoded as unpadded base64url.
func NewSessionID() (string, error) {
	var b [SessionIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session_id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ValidateSessionID verifies that id is a canonical unpadded base64url 128-bit identifier.
func ValidateSessionID(id string) error {
	if len(id) != SessionIDEncodedLen {
		return ErrInvalidSessionID
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != SessionIDBytes {
		return ErrInvalidSessionID
	}
	if base64.RawURLEncoding.EncodeToString(raw) != id {
		return ErrInvalidSessionID
	}
	return nil
}

// NewChallenge generates a cryptographically random single-use challenge (>= 32 bytes) as unpadded base64url.
func NewChallenge() (string, error) {
	var b [ChallengeBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// SignEnvelope constructs, validates, and signs a peer-to-peer SignalEnvelope using RFC 8785 JCS.
func SignEnvelope(
	kp *identity.KeyPair,
	msgType string,
	toPeerID string,
	sessionID string,
	generation uint32,
	seq uint64,
	expiresAt int64,
	body any,
) (*SignalEnvelope, []byte, error) {
	if !IsPeerSignalType(msgType) {
		return nil, nil, ErrUnknownType
	}
	if err := identity.ValidatePeerID(kp.PeerID); err != nil {
		return nil, nil, err
	}
	if err := identity.ValidatePeerID(toPeerID); err != nil || kp.PeerID == toPeerID {
		return nil, nil, ErrInvalidEnvelope
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, nil, err
	}
	bodyBytes, err := jcs.MarshalCanonical(body)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateBody(msgType, bodyBytes); err != nil {
		return nil, nil, err
	}

	unsigned := unsignedSignalEnvelope{
		V:          Version,
		Type:       msgType,
		From:       kp.PeerID,
		To:         toPeerID,
		SessionID:  sessionID,
		Generation: generation,
		Seq:        seq,
		ExpiresAt:  expiresAt,
		Body:       bodyBytes,
	}
	canon, err := jcs.MarshalCanonical(unsigned)
	if err != nil {
		return nil, nil, err
	}
	signingInput := make([]byte, 0, len(DomainSignalV1)+len(canon))
	signingInput = append(signingInput, DomainSignalV1...)
	signingInput = append(signingInput, canon...)
	sig := ed25519.Sign(kp.PrivateKey, signingInput)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	env := &SignalEnvelope{
		V:          unsigned.V,
		Type:       unsigned.Type,
		From:       unsigned.From,
		To:         unsigned.To,
		SessionID:  unsigned.SessionID,
		Generation: unsigned.Generation,
		Seq:        unsigned.Seq,
		ExpiresAt:  unsigned.ExpiresAt,
		Body:       unsigned.Body,
		Sig:        sigEnc,
	}
	rawOut, err := json.Marshal(env)
	if err != nil {
		return nil, nil, err
	}
	if len(rawOut) > MaxSignalingMessageSize {
		return nil, nil, ErrMessageTooLarge
	}
	return env, rawOut, nil
}

// ParseUnsignedEnvelope strictly parses and validates all schema fields of a raw
// SignalEnvelope prior to cryptographic signature verification.
func ParseUnsignedEnvelope(raw []byte, maxBytes int) (*SignalEnvelope, error) {
	if maxBytes <= 0 {
		maxBytes = MaxSignalingMessageSize
	}
	if len(raw) > maxBytes {
		return nil, ErrMessageTooLarge
	}
	// Ensure all required envelope fields exist and no extra fields or duplicate keys appear.
	var strictCheck struct {
		V          *int             `json:"v"`
		Type       *string          `json:"type"`
		From       *string          `json:"from"`
		To         *string          `json:"to"`
		SessionID  *string          `json:"session_id"`
		Generation *int64           `json:"generation"`
		Seq        *int64           `json:"seq"`
		ExpiresAt  *int64           `json:"expires_at"`
		Body       *json.RawMessage `json:"body"`
		Sig        *string          `json:"sig"`
	}
	if err := jcs.UnmarshalStrict(raw, &strictCheck); err != nil {
		return nil, err
	}
	if strictCheck.V == nil || strictCheck.Type == nil || strictCheck.From == nil ||
		strictCheck.To == nil || strictCheck.SessionID == nil || strictCheck.Generation == nil ||
		strictCheck.Seq == nil || strictCheck.ExpiresAt == nil || strictCheck.Body == nil ||
		strictCheck.Sig == nil {
		return nil, ErrInvalidEnvelope
	}
	if *strictCheck.V != Version {
		return nil, ErrUnsupportedVer
	}
	if !IsPeerSignalType(*strictCheck.Type) {
		return nil, ErrUnknownType
	}
	if err := identity.ValidatePeerID(*strictCheck.From); err != nil {
		return nil, ErrInvalidEnvelope
	}
	if err := identity.ValidatePeerID(*strictCheck.To); err != nil || *strictCheck.From == *strictCheck.To {
		return nil, ErrInvalidEnvelope
	}
	if err := ValidateSessionID(*strictCheck.SessionID); err != nil {
		return nil, err
	}
	if *strictCheck.Generation < 0 || *strictCheck.Generation > 0x7fffffff {
		return nil, ErrInvalidEnvelope
	}
	if *strictCheck.Seq < 0 {
		return nil, ErrInvalidEnvelope
	}
	if err := ValidateBody(*strictCheck.Type, *strictCheck.Body); err != nil {
		return nil, err
	}

	return &SignalEnvelope{
		V:          *strictCheck.V,
		Type:       *strictCheck.Type,
		From:       *strictCheck.From,
		To:         *strictCheck.To,
		SessionID:  *strictCheck.SessionID,
		Generation: uint32(*strictCheck.Generation),
		Seq:        uint64(*strictCheck.Seq),
		ExpiresAt:  *strictCheck.ExpiresAt,
		Body:       *strictCheck.Body,
		Sig:        *strictCheck.Sig,
	}, nil
}

// VerifyEnvelopeSignature checks expiry bounds and verifies the Ed25519 signature over
// "LIGHTHOUSE-SIGNAL-V1\x00" + JCS(envelope without sig).
func VerifyEnvelopeSignature(
	env *SignalEnvelope,
	senderPub ed25519.PublicKey,
	now time.Time,
	maxTTL time.Duration,
	clockSkew time.Duration,
) error {
	if env == nil {
		return ErrInvalidEnvelope
	}
	derivedID, err := identity.PeerIDFromPublicKey(senderPub)
	if err != nil || derivedID != env.From {
		return ErrInvalidSignature
	}
	nowUnix := now.Unix()
	skewSec := int64(clockSkew / time.Second)
	ttlSec := int64(maxTTL / time.Second)
	if env.ExpiresAt+skewSec < nowUnix || env.ExpiresAt > nowUnix+ttlSec+skewSec {
		return ErrExpiredEnvelope
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(env.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sigBytes) != env.Sig {
		return ErrInvalidSignature
	}

	unsigned := unsignedSignalEnvelope{
		V:          env.V,
		Type:       env.Type,
		From:       env.From,
		To:         env.To,
		SessionID:  env.SessionID,
		Generation: env.Generation,
		Seq:        env.Seq,
		ExpiresAt:  env.ExpiresAt,
		Body:       env.Body,
	}
	canon, err := jcs.MarshalCanonical(unsigned)
	if err != nil {
		return err
	}
	signingInput := make([]byte, 0, len(DomainSignalV1)+len(canon))
	signingInput = append(signingInput, DomainSignalV1...)
	signingInput = append(signingInput, canon...)
	if !ed25519.Verify(senderPub, signingInput, sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// ValidateBody validates type-specific body schemas strictly.
func ValidateBody(msgType string, rawBody []byte) error {
	if len(rawBody) == 0 {
		return ErrInvalidBody
	}
	switch msgType {
	case TypeOffer, TypeAnswer:
		var b SDPBody
		if err := jcs.UnmarshalStrict(rawBody, &b); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBody, err)
		}
		if len(b.SDP) == 0 {
			return fmt.Errorf("%w: empty SDP", ErrInvalidBody)
		}
		return nil

	case TypeCandidate:
		var b CandidateBody
		if err := jcs.UnmarshalStrict(rawBody, &b); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBody, err)
		}
		if len(b.Candidate) == 0 || len(b.Candidate) > 2048 || len(b.UsernameFragment) > 256 {
			return fmt.Errorf("%w: invalid candidate fields", ErrInvalidBody)
		}
		return nil

	case TypeEndOfCandidates:
		var b EndOfCandidatesBody
		if err := jcs.UnmarshalStrict(rawBody, &b); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBody, err)
		}
		if len(b.UsernameFragment) == 0 || len(b.UsernameFragment) > 256 {
			return fmt.Errorf("%w: invalid usernameFragment", ErrInvalidBody)
		}
		return nil

	case TypeClose:
		var b CloseBody
		if err := jcs.UnmarshalStrict(rawBody, &b); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBody, err)
		}
		if !isValidReasonCode(b.Reason) {
			return fmt.Errorf("%w: invalid close reason code", ErrInvalidBody)
		}
		return nil

	default:
		return ErrUnknownType
	}
}

func isValidReasonCode(reason string) bool {
	if len(reason) == 0 || len(reason) > 64 {
		return false
	}
	for i := 0; i < len(reason); i++ {
		c := reason[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
