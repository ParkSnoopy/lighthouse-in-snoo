package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// appVersion is the release version reported by --version (matching VERSION).
var appVersion = "0.1.0"

// loadDotEnvIfPresent reads optional LIGHTHOUSE_* runtime variables from a local
// .env file without overriding variables already set in the process environment.
func loadDotEnvIfPresent(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !strings.HasPrefix(key, "LIGHTHOUSE_") {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		_ = os.Setenv(key, val)
	}
}

func resolvedDefaultSTUNURI() string {
	if uri := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_URI")); uri != "" {
		return uri
	}
	port := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_PORT"))
	if port == "" {
		port = "5349"
	}
	if domain := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_DOMAIN")); domain != "" {
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
	if domain := strings.TrimSpace(os.Getenv("LIGHTHOUSE_STUN_DOMAIN")); domain != "" {
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
