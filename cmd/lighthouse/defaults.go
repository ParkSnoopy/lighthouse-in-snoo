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
	defaultSTUNPort   = "3478"
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
		port = "3478"
	}
	if domain := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_DOMAIN")); domain != "" {
		return formatSTUNURI(domain, port)
	}
	if domain := strings.TrimSpace(defaultSTUNDomain); domain != "" {
		return formatSTUNURI(domain, port)
	}
	return "stun:127.0.0.1:" + port
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
	if strings.Contains(d, "://") || strings.HasPrefix(strings.ToLower(d), "stun:") {
		return d
	}
	// If already host:port or [ipv6]:port, preserve explicit port.
	if _, _, err := net.SplitHostPort(d); err == nil {
		return "stun:" + d
	}
	// Bare IPv6 address without brackets.
	if ip := net.ParseIP(d); ip != nil && ip.To4() == nil {
		return "stun:[" + d + "]:" + defaultPort
	}
	return "stun:" + net.JoinHostPort(strings.Trim(d, "[]"), defaultPort)
}

func stripSTUNHost(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.TrimPrefix(d, "stun:")
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
