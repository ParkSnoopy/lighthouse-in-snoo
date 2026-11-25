package protocol

import (
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
	// Version is the v0.2.0 control-plane protocol version.
	Version = 2

	// DomainSignalV2 is the ASCII domain separator for peer-to-peer signaling envelopes.
	DomainSignalV2 = "LIGHTHOUSE-SIGNAL-V2\x00"
	// DomainBroadcastV2 is the ASCII domain separator for signed channel broadcast announcements.
	DomainBroadcastV2 = "LIGHTHOUSE-BROADCAST-V2\x00"

	// MaxSignalingMessageSize is the maximum control-plane JSON size (64 KiB).
	MaxSignalingMessageSize = 64 * 1024

	// DefaultSignalingTTL is the default signaling message lifetime (60 s).
	DefaultSignalingTTL = 60 * time.Second

	// DefaultMaxClockSkew is the maximum tolerated clock skew (30 s).
	DefaultMaxClockSkew = 30 * time.Second

	// DefaultMaxCandidatesPerGeneration bounds trickled candidates per sender/generation.
	DefaultMaxCandidatesPerGeneration = 128

	// ChallengeBytes is the single-use registration challenge length (32 bytes).
	ChallengeBytes = 32

	// ChallengeTTL is the registration challenge lifetime (60 s).
	ChallengeTTL = 60 * time.Second

	// SessionIDBytes is 128 bits (16 bytes).
	SessionIDBytes = 16
	// SessionIDEncodedLen is the base64url unpadded length of 16 bytes.
	SessionIDEncodedLen = 22

	// MaxSealedMetaBytes bounds AEAD-encrypted broadcast metadata strings.
	MaxSealedMetaBytes = 2048
)

// Control-plane message types.
const (
	TypeChallenge       = "challenge"
	TypeRegister        = "register"
	TypeRegistered      = "registered"
	TypeHeartbeat       = "heartbeat"
	TypeChannelJoin     = "channel_join"
	TypeChannelLeave    = "channel_leave"
	TypeBroadcast       = "broadcast"
	TypeChannelPeers    = "channel_peers"
	TypeOffer           = "offer"
	TypeAnswer          = "answer"
	TypeCandidate       = "candidate"
	TypeEndOfCandidates = "end_of_candidates"
	TypeClose           = "close"
	TypeError           = "error"
)

// Machine-readable failure codes.
const (
	ErrCodeMalformedMessage   = "malformed_message"
	ErrCodeMessageTooLarge    = "message_too_large"
	ErrCodeUnsupportedVersion = "unsupported_version"
	ErrCodeUnknownType        = "unknown_type"
	ErrCodeUnauthenticated    = "unauthenticated"
	ErrCodeChallengeInvalid   = "challenge_invalid"
	ErrCodeAuthFailed         = "auth_failed"
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
	ErrInvalidSignature = errors.New("protocol: invalid envelope signature")
	ErrInvalidBody      = errors.New("protocol: invalid message body")
	ErrInvalidBroadcast = errors.New("protocol: invalid broadcast message")
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
	var partial struct {
		V    *int    `json:"v"`
		Type *string `json:"type"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return BaseHeader{}, jcs.ErrInvalidJSON
	}
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

// IsKnownType reports whether msgType is a valid v0.2.0 control-plane message type.
func IsKnownType(msgType string) bool {
	switch msgType {
	case TypeChallenge, TypeRegister, TypeRegistered, TypeHeartbeat,
		TypeChannelJoin, TypeChannelLeave, TypeBroadcast, TypeChannelPeers,
		TypeOffer, TypeAnswer, TypeCandidate, TypeEndOfCandidates,
		TypeClose, TypeError:
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

// ChallengeMessage is sent by Hub -> Peer upon WSS connection.
type ChallengeMessage struct {
	V                  int    `json:"v"`
	Type               string `json:"type"`
	Challenge          string `json:"challenge"`
	HubOrigin          string `json:"hub_origin"`
	ExpiresAt          int64  `json:"expires_at"`
	PassphraseRequired bool   `json:"passphrase_required,omitempty"`
}

// RegisterMessage is sent by Peer -> Hub to prove identity key ownership and optional hub passphrase.
type RegisterMessage struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	PeerID    string `json:"peer_id"`
	PublicKey string `json:"public_key"`
	HubOrigin string `json:"hub_origin"`
	Challenge string `json:"challenge"`
	Proof     string `json:"proof"`
	HubAuth   string `json:"hub_auth,omitempty"`
}

// RelayInfo advertises universal public relay URIs and ephemeral credentials minted by the hub.
type RelayInfo struct {
	URIs       []string `json:"uris"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
	ExpiresAt  int64    `json:"expires_at,omitempty"`
}

// RegisteredMessage is sent by Hub -> Peer on successful registration.
type RegisteredMessage struct {
	V                    int        `json:"v"`
	Type                 string     `json:"type"`
	PeerID               string     `json:"peer_id"`
	ExpiresAt            int64      `json:"expires_at"`
	HeartbeatIntervalSec int        `json:"heartbeat_interval_sec"`
	Relay                *RelayInfo `json:"relay,omitempty"`
}

// HeartbeatMessage refreshes a peer's ephemeral presence lease.
type HeartbeatMessage struct {
	V    int    `json:"v"`
	Type string `json:"type"`
}

// ChannelJoinMessage subscribes a peer to passphrase-scoped broadcasts in ChannelID.
type ChannelJoinMessage struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	ChannelID string `json:"channel_id"`
}

// ChannelLeaveMessage unsubscribes a peer from ChannelID and withdraws any broadcast in it.
type ChannelLeaveMessage struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	ChannelID string `json:"channel_id"`
}

// BroadcastMessage announces or withdraws a peer's presence in a passphrase-scoped channel.
type BroadcastMessage struct {
	V          int    `json:"v"`
	Type       string `json:"type"`
	ChannelID  string `json:"channel_id"`
	Active     bool   `json:"active"`
	PeerID     string `json:"peer_id"`
	PublicKey  string `json:"public_key"`
	SealedMeta string `json:"sealed_meta,omitempty"`
	Timestamp  int64  `json:"ts"`
	Sig        string `json:"sig"`
}

type unsignedBroadcastMessage struct {
	V          int    `json:"v"`
	Type       string `json:"type"`
	ChannelID  string `json:"channel_id"`
	Active     bool   `json:"active"`
	PeerID     string `json:"peer_id"`
	PublicKey  string `json:"public_key"`
	SealedMeta string `json:"sealed_meta,omitempty"`
	Timestamp  int64  `json:"ts"`
}

// BroadcastPeer is an active signed broadcaster entry distributed within ChannelPeersMessage.
type BroadcastPeer struct {
	PeerID     string `json:"peer_id"`
	PublicKey  string `json:"public_key"`
	SealedMeta string `json:"sealed_meta,omitempty"`
	Timestamp  int64  `json:"ts"`
	Sig        string `json:"sig"`
}

// ChannelPeersMessage pushes the current active broadcasters for one passphrase-derived channel.
type ChannelPeersMessage struct {
	V         int             `json:"v"`
	Type      string          `json:"type"`
	ChannelID string          `json:"channel_id"`
	Peers     []BroadcastPeer `json:"peers"`
}

// ErrorMessage delivers bounded, machine-readable failure codes from Hub -> Peer.
type ErrorMessage struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

// SignalEnvelope is the signed peer-to-peer signaling envelope.
// Offers and answers embed the sender's PublicKey so recipients verify identity without hub ACLs.
type SignalEnvelope struct {
	V          int             `json:"v"`
	Type       string          `json:"type"`
	From       string          `json:"from"`
	To         string          `json:"to"`
	PublicKey  string          `json:"public_key,omitempty"`
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
	PublicKey  string          `json:"public_key,omitempty"`
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

// CandidateBody is the body of signed "candidate" envelopes.
type CandidateBody struct {
	Candidate        string  `json:"candidate"`
	SDPMid           *string `json:"sdpMid,omitempty"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex,omitempty"`
	UsernameFragment string  `json:"usernameFragment,omitempty"`
}

// EndOfCandidatesBody is the body of signed "end_of_candidates" envelopes.
type EndOfCandidatesBody struct {
	UsernameFragment string `json:"usernameFragment"`
}

// CloseBody is the body of signed "close" envelopes.
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

// NewChallenge generates a cryptographically random single-use challenge (32 bytes) as unpadded base64url.
func NewChallenge() (string, error) {
	var b [ChallengeBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// SignBroadcast signs a BroadcastMessage using kp's identity key and RFC 8785 JCS.
func SignBroadcast(
	kp *identity.KeyPair,
	channelID string,
	active bool,
	sealedMeta string,
	ts int64,
) (*BroadcastMessage, []byte, error) {
	if kp == nil {
		return nil, nil, identity.ErrInvalidPrivateKey
	}
	if err := identity.ValidatePeerID(kp.PeerID); err != nil {
		return nil, nil, err
	}
	if err := identity.ValidateChannelID(channelID); err != nil {
		return nil, nil, err
	}
	if len(sealedMeta) > MaxSealedMetaBytes {
		return nil, nil, ErrInvalidBroadcast
	}

	unsigned := unsignedBroadcastMessage{
		V:          Version,
		Type:       TypeBroadcast,
		ChannelID:  channelID,
		Active:     active,
		PeerID:     kp.PeerID,
		PublicKey:  identity.EncodePublicKey(kp.PublicKey),
		SealedMeta: sealedMeta,
		Timestamp:  ts,
	}
	canon, err := jcs.MarshalCanonical(unsigned)
	if err != nil {
		return nil, nil, err
	}
	signingInput := make([]byte, 0, len(DomainBroadcastV2)+len(canon))
	signingInput = append(signingInput, DomainBroadcastV2...)
	signingInput = append(signingInput, canon...)
	sigEnc, err := kp.SignBase64URL(signingInput)
	if err != nil {
		return nil, nil, err
	}

	msg := &BroadcastMessage{
		V:          unsigned.V,
		Type:       unsigned.Type,
		ChannelID:  unsigned.ChannelID,
		Active:     unsigned.Active,
		PeerID:     unsigned.PeerID,
		PublicKey:  unsigned.PublicKey,
		SealedMeta: unsigned.SealedMeta,
		Timestamp:  unsigned.Timestamp,
		Sig:        sigEnc,
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > MaxSignalingMessageSize {
		return nil, nil, ErrMessageTooLarge
	}
	return msg, raw, nil
}

// VerifyBroadcast validates a BroadcastMessage's schema, public key binding, and cryptographic signature.
func VerifyBroadcast(msg *BroadcastMessage) (identity.PublicKey, error) {
	if msg == nil || msg.V != Version || msg.Type != TypeBroadcast {
		return identity.PublicKey{}, ErrInvalidBroadcast
	}
	if err := identity.ValidateChannelID(msg.ChannelID); err != nil {
		return identity.PublicKey{}, ErrInvalidBroadcast
	}
	if err := identity.ValidatePeerID(msg.PeerID); err != nil {
		return identity.PublicKey{}, ErrInvalidBroadcast
	}
	if len(msg.SealedMeta) > MaxSealedMetaBytes {
		return identity.PublicKey{}, ErrInvalidBroadcast
	}
	pub, err := identity.DecodePublicKey(msg.PublicKey)
	if err != nil {
		return identity.PublicKey{}, ErrInvalidBroadcast
	}
	derivedID, err := identity.PeerIDFromPublicKey(pub)
	if err != nil || derivedID != msg.PeerID {
		return identity.PublicKey{}, identity.ErrPeerIDMismatch
	}
	unsigned := unsignedBroadcastMessage{
		V:          msg.V,
		Type:       msg.Type,
		ChannelID:  msg.ChannelID,
		Active:     msg.Active,
		PeerID:     msg.PeerID,
		PublicKey:  msg.PublicKey,
		SealedMeta: msg.SealedMeta,
		Timestamp:  msg.Timestamp,
	}
	canon, err := jcs.MarshalCanonical(unsigned)
	if err != nil {
		return identity.PublicKey{}, err
	}
	signingInput := make([]byte, 0, len(DomainBroadcastV2)+len(canon))
	signingInput = append(signingInput, DomainBroadcastV2...)
	signingInput = append(signingInput, canon...)
	if err := pub.VerifyBase64URL(signingInput, msg.Sig); err != nil {
		return identity.PublicKey{}, ErrInvalidSignature
	}
	return pub, nil
}

// VerifyBroadcastPeer verifies an active BroadcastPeer entry received in ChannelPeersMessage.
func VerifyBroadcastPeer(channelID string, bp BroadcastPeer) (identity.PublicKey, error) {
	return VerifyBroadcast(&BroadcastMessage{
		V:          Version,
		Type:       TypeBroadcast,
		ChannelID:  channelID,
		Active:     true,
		PeerID:     bp.PeerID,
		PublicKey:  bp.PublicKey,
		SealedMeta: bp.SealedMeta,
		Timestamp:  bp.Timestamp,
		Sig:        bp.Sig,
	})
}

// SignEnvelope constructs, validates, and signs a peer-to-peer SignalEnvelope using RFC 8785 JCS.
// Offers and answers automatically embed the sender's PublicKey for hub-independent verification.
func SignEnvelope(
	kp *identity.KeyPair,
	msgType, toPeerID, sessionID string,
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

	pubEnc := ""
	if msgType == TypeOffer || msgType == TypeAnswer || msgType == TypeClose {
		pubEnc = identity.EncodePublicKey(kp.PublicKey)
	}

	unsigned := unsignedSignalEnvelope{
		V:          Version,
		Type:       msgType,
		From:       kp.PeerID,
		To:         toPeerID,
		PublicKey:  pubEnc,
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
	signingInput := make([]byte, 0, len(DomainSignalV2)+len(canon))
	signingInput = append(signingInput, DomainSignalV2...)
	signingInput = append(signingInput, canon...)
	sigEnc, err := kp.SignBase64URL(signingInput)
	if err != nil {
		return nil, nil, err
	}

	env := &SignalEnvelope{
		V:          unsigned.V,
		Type:       unsigned.Type,
		From:       unsigned.From,
		To:         unsigned.To,
		PublicKey:  unsigned.PublicKey,
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
	var strictCheck struct {
		V          *int             `json:"v"`
		Type       *string          `json:"type"`
		From       *string          `json:"from"`
		To         *string          `json:"to"`
		PublicKey  *string          `json:"public_key,omitempty"`
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

	pubEnc := ""
	if strictCheck.PublicKey != nil {
		pubEnc = *strictCheck.PublicKey
	}

	return &SignalEnvelope{
		V:          *strictCheck.V,
		Type:       *strictCheck.Type,
		From:       *strictCheck.From,
		To:         *strictCheck.To,
		PublicKey:  pubEnc,
		SessionID:  *strictCheck.SessionID,
		Generation: uint32(*strictCheck.Generation),
		Seq:        uint64(*strictCheck.Seq),
		ExpiresAt:  *strictCheck.ExpiresAt,
		Body:       *strictCheck.Body,
		Sig:        *strictCheck.Sig,
	}, nil
}

// VerifyEnvelopeSignature checks expiry bounds and verifies the signature over
// "LIGHTHOUSE-SIGNAL-V2\x00" + JCS(envelope without sig).
func VerifyEnvelopeSignature(
	env *SignalEnvelope,
	senderPub identity.PublicKey,
	now time.Time,
	maxTTL, clockSkew time.Duration,
) error {
	if env == nil {
		return ErrInvalidEnvelope
	}
	derivedID, err := identity.PeerIDFromPublicKey(senderPub)
	if err != nil || derivedID != env.From {
		return ErrInvalidSignature
	}
	if env.PublicKey != "" {
		embeddedPub, decErr := identity.DecodePublicKey(env.PublicKey)
		if decErr != nil || !embeddedPub.Equal(senderPub) {
			return ErrInvalidSignature
		}
	}
	nowUnix := now.Unix()
	skewSec := int64(clockSkew / time.Second)
	ttlSec := int64(maxTTL / time.Second)
	if env.ExpiresAt+skewSec < nowUnix || env.ExpiresAt > nowUnix+ttlSec+skewSec {
		return ErrExpiredEnvelope
	}

	unsigned := unsignedSignalEnvelope{
		V:          env.V,
		Type:       env.Type,
		From:       env.From,
		To:         env.To,
		PublicKey:  env.PublicKey,
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
	signingInput := make([]byte, 0, len(DomainSignalV2)+len(canon))
	signingInput = append(signingInput, DomainSignalV2...)
	signingInput = append(signingInput, canon...)
	if err := senderPub.VerifyBase64URL(signingInput, env.Sig); err != nil {
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
		if b.SDP == "" {
			return fmt.Errorf("%w: empty SDP", ErrInvalidBody)
		}
		return nil

	case TypeCandidate:
		var b CandidateBody
		if err := jcs.UnmarshalStrict(rawBody, &b); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBody, err)
		}
		if b.Candidate == "" || len(b.Candidate) > 2048 || len(b.UsernameFragment) > 256 {
			return fmt.Errorf("%w: invalid candidate fields", ErrInvalidBody)
		}
		return nil

	case TypeEndOfCandidates:
		var b EndOfCandidatesBody
		if err := jcs.UnmarshalStrict(rawBody, &b); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBody, err)
		}
		if b.UsernameFragment == "" || len(b.UsernameFragment) > 256 {
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
	if reason == "" || len(reason) > 64 {
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
