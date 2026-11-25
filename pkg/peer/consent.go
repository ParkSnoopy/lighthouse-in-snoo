package peer

import (
	"context"
	"net/netip"

	"lighthouse-in-snoo/pkg/identity"
)

// ConsentDecision represents the user's explicit authorization choice for an incoming connection.
// The zero value is ConsentDeny so omitted handlers always fail closed.
type ConsentDecision int

const (
	ConsentDeny ConsentDecision = iota
	ConsentAllow
	ConsentBlacklist
)

// String returns a terse label for the decision.
func (d ConsentDecision) String() string {
	switch d {
	case ConsentAllow:
		return "allow"
	case ConsentBlacklist:
		return "blacklist"
	default:
		return "deny"
	}
}

// IncomingRequest describes a cryptographically verified incoming peer connection request
// presented to the user before any WebRTC answer or TUN route is established.
type IncomingRequest struct {
	PeerID           string
	PublicKey        identity.PublicKey
	Algorithm        identity.Algorithm
	VirtualIP        netip.Addr
	DisplayName      string
	ChannelID        string
	DTLSFingerprints []string
	SessionID        string
}

// ConsentHandler decides whether an incoming connection is allowed, denied, or blacklisted.
type ConsentHandler interface {
	AuthorizeIncoming(ctx context.Context, req *IncomingRequest) ConsentDecision
}

// ConsentFunc adapts a function into a ConsentHandler.
type ConsentFunc func(ctx context.Context, req *IncomingRequest) ConsentDecision

// AuthorizeIncoming invokes f.
func (f ConsentFunc) AuthorizeIncoming(ctx context.Context, req *IncomingRequest) ConsentDecision {
	if f == nil || req == nil {
		return ConsentDeny
	}
	return f(ctx, req)
}

// DiscoveredPeer represents an active peer broadcasting under a shared offline passphrase.
type DiscoveredPeer struct {
	PeerID      string
	PublicKey   identity.PublicKey
	Algorithm   identity.Algorithm
	VirtualIP   netip.Addr
	DisplayName string
	ChannelID   string
	Timestamp   int64
}
