package peer

import "errors"

// ConnectionState models the normative peer connection state machine (Section 5.2).
type ConnectionState string

const (
	StateDisconnected   ConnectionState = "Disconnected"
	StateDiscovering    ConnectionState = "Discovering"
	StateNegotiating    ConnectionState = "Negotiating"
	StateAuthenticating ConnectionState = "Authenticating"
	StateConnected      ConnectionState = "Connected"
	StateReconnecting   ConnectionState = "Reconnecting"
	StateFailed         ConnectionState = "Failed"
)

// DataChannel labels defined in Section 7.
const (
	ChannelLabelDataV1   = "data/v1"
	ChannelLabelPacketV1 = "packet/v1"

	// MaxApplicationMessageBytes is the initial per-message payload limit (16 KiB, Section 7).
	MaxApplicationMessageBytes = 16 * 1024
	// DefaultApplicationQueueBytes is the bounded outbound queue limit per peer (1 MiB, Section 9).
	DefaultApplicationQueueBytes = 1024 * 1024

	// ExpectedDTLS13HexVersion is the RFC 9147 DTLS 1.3 version code (0xFEFC) reported by Pion TransportStats.
	ExpectedDTLS13HexVersion = "FEFC"
)

var (
	ErrProhibitedCandidate   = errors.New("peer: prohibited relay or non-UDP ICE candidate")
	ErrProhibitedEndpoint    = errors.New("peer: prohibited hub service endpoint in candidate")
	ErrInvalidICEConfig      = errors.New("peer: invalid or prohibited ICE server configuration")
	ErrInsecureICEProhibited = errors.New("peer: plaintext stun:/turn: requires opt-in --insecure; use stuns:/turns:")
	ErrInvalidRemoteSDP      = errors.New("peer: invalid or insecure remote SDP")
	ErrFingerprintMismatch   = errors.New("peer: DTLS certificate fingerprint mismatch")
	ErrDTLSVersionDowngrade  = errors.New("peer: negotiated DTLS version is not DTLS 1.3")
	ErrUnverifiedPath        = errors.New("peer: authenticated path is not verified")
	ErrMessageTooLarge       = errors.New("peer: message exceeds negotiated 16 KiB limit")
	ErrSessionClosed         = errors.New("peer: session is closed or failed")
	ErrPeerOfflineOrDenied   = errors.New("peer: target peer offline or denied")
	ErrHubDisconnected       = errors.New("peer: control-plane WSS connection unavailable")
	ErrReplayedSignaling     = errors.New("peer: replayed signaling envelope rejected")
	ErrStaleGeneration       = errors.New("peer: stale ICE generation rejected")
	ErrCandidateLimit        = errors.New("peer: trickled candidate limit exceeded")
	ErrConnectTimeout        = errors.New("peer: offer-to-connected deadline exceeded")
	ErrRestartExhausted      = errors.New("peer: ICE restart retry budget exhausted")
)

// SessionDiagnostics exposes non-sensitive connection state and transport metrics (Section 9 & 10).
type SessionDiagnostics struct {
	RemotePeerID        string
	SessionID           string
	Generation          uint32
	State               ConnectionState
	LocalCandidateType  string
	RemoteCandidateType string
	SelectedPair        string
	DTLSVersion         string
	DTLSCipher          string
	RemoteCertSHA256    string
	RTTSeconds          float64
	BytesSent           uint64
	BytesReceived       uint64
	FailureCode         string
}
