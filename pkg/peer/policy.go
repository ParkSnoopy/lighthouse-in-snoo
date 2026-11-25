package peer

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/pion/ice/v5"
	"github.com/pion/sdp/v3"
	"github.com/pion/stun/v5"
	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/pkg/protocol"
)

// RemoteSDPInfo summarizes security-relevant attributes extracted from a verified SDP.
type RemoteSDPInfo struct {
	SHA256Fingerprints []string
	ICEUfrag           string
	ICEPwd             string
	MaxMessageSize     int
}

// ValidateSTUNServerURI enforces Section 5.1: only UDP stun: URIs are permitted;
// turn:, turns:, stuns:, TCP transports, or embedded credentials are prohibited.
func ValidateSTUNServerURI(rawURI string) error {
	if rawURI == "" {
		return nil
	}
	parsed, err := stun.ParseURI(rawURI)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidICEConfig, err)
	}
	if parsed.Scheme != stun.SchemeTypeSTUN || parsed.Proto != stun.ProtoTypeUDP {
		return fmt.Errorf("%w: scheme=%s proto=%s", ErrInvalidICEConfig, parsed.Scheme, parsed.Proto)
	}
	if parsed.Host == "" || parsed.Port <= 0 || parsed.Port > 65535 {
		return fmt.Errorf("%w: invalid STUN host/port", ErrInvalidICEConfig)
	}
	return nil
}

// ValidateAndInspectRemoteSDP parses a remote SDP prior to installation in WebRTC
// and enforces data-only media, SHA-256 DTLS fingerprints, non-empty ICE credentials,
// and the direct-only candidate policy (rejecting relay/TCP/hub-endpoint candidates).
func ValidateAndInspectRemoteSDP(
	rawSDP string,
	prohibitedEndpoints []net.UDPAddr,
	prohibitedIPs []net.IP,
) (RemoteSDPInfo, error) {
	var parsed sdp.SessionDescription
	if err := parsed.Unmarshal([]byte(rawSDP)); err != nil {
		return RemoteSDPInfo{}, fmt.Errorf("%w: %v", ErrInvalidRemoteSDP, err)
	}
	if len(parsed.MediaDescriptions) == 0 {
		return RemoteSDPInfo{}, fmt.Errorf("%w: missing media section", ErrInvalidRemoteSDP)
	}

	var fps []string
	collectFingerprints := func(attrs []sdp.Attribute) error {
		for _, a := range attrs {
			if !strings.EqualFold(a.Key, "fingerprint") {
				continue
			}
			parts := strings.Fields(a.Value)
			if len(parts) != 2 {
				return fmt.Errorf("%w: malformed fingerprint attribute", ErrInvalidRemoteSDP)
			}
			if !strings.EqualFold(parts[0], "sha-256") {
				return fmt.Errorf("%w: unsupported fingerprint hash %q", ErrInvalidRemoteSDP, parts[0])
			}
			norm, err := normalizeSHA256Fingerprint(parts[1])
			if err != nil {
				return err
			}
			fps = append(fps, norm)
		}
		return nil
	}

	if err := collectFingerprints(parsed.Attributes); err != nil {
		return RemoteSDPInfo{}, err
	}

	var ufrag, pwd string
	if v, ok := parsed.Attribute("ice-ufrag"); ok {
		ufrag = v
	}
	if v, ok := parsed.Attribute("ice-pwd"); ok {
		pwd = v
	}

	maxMsgSize := MaxApplicationMessageBytes

	// Check session-level candidates if any.
	for _, a := range parsed.Attributes {
		if strings.EqualFold(a.Key, "candidate") {
			if err := validateCandidateString(a.Value, prohibitedEndpoints, prohibitedIPs); err != nil {
				return RemoteSDPInfo{}, err
			}
		}
	}

	for _, md := range parsed.MediaDescriptions {
		// Profile is strictly data-channel-only ("application" media type).
		if !strings.EqualFold(md.MediaName.Media, "application") {
			return RemoteSDPInfo{}, fmt.Errorf("%w: non-data media %q prohibited", ErrInvalidRemoteSDP, md.MediaName.Media)
		}
		if err := collectFingerprints(md.Attributes); err != nil {
			return RemoteSDPInfo{}, err
		}
		if v, ok := md.Attribute("ice-ufrag"); ok && ufrag == "" {
			ufrag = v
		}
		if v, ok := md.Attribute("ice-pwd"); ok && pwd == "" {
			pwd = v
		}
		if v, ok := md.Attribute(" ice-lite"); ok || hasAttr(md.Attributes, "ice-lite") || hasAttr(parsed.Attributes, "ice-lite") {
			_ = v
			return RemoteSDPInfo{}, fmt.Errorf("%w: ice-lite prohibited; full ICE required", ErrInvalidRemoteSDP)
		}
		if v, ok := md.Attribute("max-message-size"); ok {
			if parsedMax, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && parsedMax > 0 && parsedMax < maxMsgSize {
				maxMsgSize = parsedMax
			}
		}
		for _, a := range md.Attributes {
			if strings.EqualFold(a.Key, "candidate") {
				if err := validateCandidateString(a.Value, prohibitedEndpoints, prohibitedIPs); err != nil {
					return RemoteSDPInfo{}, err
				}
			}
		}
	}

	if len(fps) == 0 {
		return RemoteSDPInfo{}, fmt.Errorf("%w: missing sha-256 fingerprint", ErrInvalidRemoteSDP)
	}
	if strings.TrimSpace(ufrag) == "" || strings.TrimSpace(pwd) == "" {
		return RemoteSDPInfo{}, fmt.Errorf("%w: missing ICE credentials", ErrInvalidRemoteSDP)
	}

	return RemoteSDPInfo{
		SHA256Fingerprints: fps,
		ICEUfrag:           ufrag,
		ICEPwd:             pwd,
		MaxMessageSize:     maxMsgSize,
	}, nil
}

// ValidateTrickleCandidate inspects a trickled ICE candidate prior to installation.
func ValidateTrickleCandidate(
	body protocol.CandidateBody,
	prohibitedEndpoints []net.UDPAddr,
	prohibitedIPs []net.IP,
) error {
	trimmed := strings.TrimSpace(body.Candidate)
	if trimmed == "" {
		return ErrProhibitedCandidate
	}
	return validateCandidateString(trimmed, prohibitedEndpoints, prohibitedIPs)
}

func validateCandidateString(
	rawCand string,
	prohibitedEndpoints []net.UDPAddr,
	prohibitedIPs []net.IP,
) error {
	spec := strings.TrimSpace(rawCand)
	spec = strings.TrimPrefix(spec, "a=")
	spec = strings.TrimPrefix(spec, "candidate:")
	if spec == "" {
		return ErrProhibitedCandidate
	}

	cand, err := ice.UnmarshalCandidate(spec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProhibitedCandidate, err)
	}
	if !cand.NetworkType().IsUDP() {
		return fmt.Errorf("%w: non-UDP network %s", ErrProhibitedCandidate, cand.NetworkType())
	}
	switch cand.Type() {
	case ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypePeerReflexive:
	case ice.CandidateTypeRelay:
		return fmt.Errorf("%w: relay candidate prohibited", ErrProhibitedCandidate)
	default:
		return fmt.Errorf("%w: unsupported candidate type %s", ErrProhibitedCandidate, cand.Type())
	}

	candIP := parseCandidateIP(cand.Address())
	candPort := cand.Port()
	if err := checkProhibitedDestination(candIP, candPort, prohibitedEndpoints, prohibitedIPs); err != nil {
		return err
	}
	return nil
}

// ValidateSelectedPair validates the nominated local and remote ICE candidates (Section 5.1).
func ValidateSelectedPair(
	pair *webrtc.ICECandidatePair,
	prohibitedEndpoints []net.UDPAddr,
	prohibitedIPs []net.IP,
) error {
	if pair == nil || pair.Local == nil || pair.Remote == nil {
		return ErrUnverifiedPath
	}
	if pair.Local.Protocol != webrtc.ICEProtocolUDP || pair.Remote.Protocol != webrtc.ICEProtocolUDP {
		return fmt.Errorf("%w: non-UDP selected candidate pair", ErrProhibitedCandidate)
	}
	if !isAllowedWebRTCCandidateType(pair.Local.Typ) || !isAllowedWebRTCCandidateType(pair.Remote.Typ) {
		return fmt.Errorf(
			"%w: selected pair (%s, %s)",
			ErrProhibitedCandidate,
			pair.Local.Typ.String(),
			pair.Remote.Typ.String(),
		)
	}
	remoteIP := parseCandidateIP(pair.Remote.Address)
	if err := checkProhibitedDestination(remoteIP, int(pair.Remote.Port), prohibitedEndpoints, prohibitedIPs); err != nil {
		return err
	}
	return nil
}

func parseCandidateIP(raw string) net.IP {
	if ip := net.ParseIP(raw); ip != nil {
		return ip
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return net.IP(addr.AsSlice())
	}
	return nil
}

func isAllowedWebRTCCandidateType(t webrtc.ICECandidateType) bool {
	switch t {
	case webrtc.ICECandidateTypeHost, webrtc.ICECandidateTypeSrflx, webrtc.ICECandidateTypePrflx:
		return true
	default:
		return false
	}
}

func checkProhibitedDestination(
	ip net.IP,
	port int,
	prohibitedEndpoints []net.UDPAddr,
	prohibitedIPs []net.IP,
) error {
	if ip == nil || port <= 0 || port > 65535 {
		return ErrProhibitedEndpoint
	}
	for _, ep := range prohibitedEndpoints {
		if ep.Port == port && ep.IP != nil && ep.IP.Equal(ip) {
			return fmt.Errorf("%w: matches hub endpoint %s", ErrProhibitedEndpoint, ep.String())
		}
	}
	for _, blockedIP := range prohibitedIPs {
		if blockedIP != nil && blockedIP.Equal(ip) {
			return fmt.Errorf("%w: matches prohibited hub IP %s", ErrProhibitedEndpoint, ip.String())
		}
	}
	return nil
}

// VerifyRemoteCertSHA256 parses the DER-encoded peer certificate from DTLS and confirms
// its SHA-256 digest matches an Ed25519-authenticated fingerprint from the remote SDP.
func VerifyRemoteCertSHA256(rawDER []byte, expectedFingerprints []string) (string, error) {
	if len(rawDER) == 0 || len(expectedFingerprints) == 0 {
		return "", ErrFingerprintMismatch
	}
	if _, err := x509.ParseCertificate(rawDER); err != nil {
		return "", fmt.Errorf("%w: %v", ErrFingerprintMismatch, err)
	}
	sum := sha256.Sum256(rawDER)
	actual := formatSHA256Fingerprint(sum[:])
	for _, exp := range expectedFingerprints {
		if strings.EqualFold(actual, exp) {
			return actual, nil
		}
	}
	return "", fmt.Errorf("%w: got %s", ErrFingerprintMismatch, actual)
}

func normalizeSHA256Fingerprint(fp string) (string, error) {
	parts := strings.Split(strings.TrimSpace(fp), ":")
	if len(parts) != sha256.Size {
		return "", fmt.Errorf("%w: invalid sha-256 fingerprint length", ErrInvalidRemoteSDP)
	}
	var out [sha256.Size]byte
	for i, p := range parts {
		if len(p) != 2 {
			return "", fmt.Errorf("%w: invalid fingerprint byte %q", ErrInvalidRemoteSDP, p)
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return "", fmt.Errorf("%w: invalid fingerprint hex", ErrInvalidRemoteSDP)
		}
		out[i] = byte(v)
	}
	return formatSHA256Fingerprint(out[:]), nil
}

func formatSHA256Fingerprint(b []byte) string {
	const hexDigits = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(b)*3 - 1)
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(hexDigits[v>>4])
		sb.WriteByte(hexDigits[v&0x0f])
	}
	return sb.String()
}

func hasAttr(attrs []sdp.Attribute, key string) bool {
	for _, a := range attrs {
		if strings.EqualFold(a.Key, key) {
			return true
		}
	}
	return false
}
