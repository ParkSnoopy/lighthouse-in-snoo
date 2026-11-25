package main

import (
	"net"
	"os"
	"strings"
)

// Build-time injectable defaults (set via -ldflags "-X main.<var>=...").
var (
	appVersion        = "0.1.0"
	defaultSTUNDomain = ""
	defaultSTUNPort   = "5349"
	defaultHubOrigin  = ""
)

func resolvedDefaultSTUNURI() string {
	if uri := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_URI")); uri != "" {
		return uri
	}
	port := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_PORT"))
	if port == "" {
		port = strings.TrimSpace(defaultSTUNPort)
	}
	if port == "" {
		port = "5349"
	}
	if domain := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_DOMAIN")); domain != "" {
		return formatSTUNURI(domain, port)
	}
	if domain := strings.TrimSpace(defaultSTUNDomain); domain != "" {
		return formatSTUNURI(domain, port)
	}
	return "stuns:127.0.0.1:" + port
}

func resolvedDefaultTURNURI() string {
	return strings.TrimSpace(os.Getenv("LIGHTHOUSE_TURN_URI"))
}

func resolvedDefaultHubOrigin() string {
	if origin := strings.TrimSpace(os.Getenv("LIGHTHOUSE_HUB_ORIGIN")); origin != "" {
		return origin
	}
	if origin := strings.TrimSpace(defaultHubOrigin); origin != "" {
		return origin
	}
	if domain := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_DOMAIN")); domain != "" {
		return "wss://" + stripSTUNHost(domain)
	}
	if domain := strings.TrimSpace(defaultSTUNDomain); domain != "" {
		return "wss://" + stripSTUNHost(domain)
	}
	return "wss://localhost:8443"
}

func resolvedDefaultHubURL() string {
	if u := strings.TrimSpace(os.Getenv("LIGHTHOUSE_HUB_URL")); u != "" {
		return u
	}
	return strings.TrimRight(resolvedDefaultHubOrigin(), "/") + "/v1/signal"
}

func formatSTUNURI(domain, defaultPort string) string {
	d := strings.TrimSpace(domain)
	lower := strings.ToLower(d)
	if strings.Contains(d, "://") ||
		strings.HasPrefix(lower, "stuns:") ||
		strings.HasPrefix(lower, "turns:") ||
		strings.HasPrefix(lower, "stun:") ||
		strings.HasPrefix(lower, "turn:") {
		return d
	}
	// If already host:port or [ipv6]:port, preserve explicit port.
	if _, _, err := net.SplitHostPort(d); err == nil {
		return "stuns:" + d
	}
	// Bare IPv6 address without brackets.
	if ip := net.ParseIP(d); ip != nil && ip.To4() == nil {
		return "stuns:[" + d + "]:" + defaultPort
	}
	return "stuns:" + net.JoinHostPort(strings.Trim(d, "[]"), defaultPort)
}

func stripSTUNHost(domain string) string {
	d := strings.TrimSpace(domain)
	lower := strings.ToLower(d)
	for _, prefix := range []string{"stuns:", "turns:", "stun:", "turn:"} {
		if strings.HasPrefix(lower, prefix) {
			d = d[len(prefix):]
			break
		}
	}
	if qIdx := strings.IndexByte(d, '?'); qIdx >= 0 {
		d = d[:qIdx]
	}
	if host, _, err := net.SplitHostPort(d); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return "[" + host + "]"
		}
		return host
	}
	if ip := net.ParseIP(d); ip != nil && ip.To4() == nil {
		return "[" + d + "]"
	}
	return d
}
