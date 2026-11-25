package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// DomainConfig holds normalized host/origin components derived from a single domain setting.
type DomainConfig struct {
	// HostPort is the canonical authority ("hub.example.com", "hub.example.com:8443", or "[::1]:8443").
	// Explicit port 443 is elided to match canonical WSS origins.
	HostPort string
	// Hostname is the unbracketed lowercased host/IP ("hub.example.com", "203.0.113.10", or "::1").
	Hostname string
}

// HubOrigin returns the canonical WSS origin ("wss://" + HostPort).
func (d DomainConfig) HubOrigin() string {
	return "wss://" + d.HostPort
}

// HubURL returns the canonical WSS signaling endpoint URL ("wss://" + HostPort + "/v1/signal").
func (d DomainConfig) HubURL() string {
	return "wss://" + d.HostPort + "/v1/signal"
}

// LoadDotEnvIfPresent reads optional LIGHTHOUSE_* runtime variables from a local
// .env file without overriding variables already set in the process environment.
func LoadDotEnvIfPresent(path string) {
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

// NormalizeDomain parses and validates a single domain/host setting such as
// "hub.example.com", "hub.example.com:8443", "203.0.113.10", or "[::1]:8443".
// If a URL scheme (wss://, https://, stuns:, turns:) or path is pasted, the authority is extracted cleanly.
func NormalizeDomain(raw string) (DomainConfig, error) {
	d := strings.TrimSpace(raw)
	if d == "" {
		return DomainConfig{}, errors.New("domain must not be empty")
	}

	var authority string
	if strings.Contains(d, "://") {
		u, err := url.Parse(d)
		if err != nil || u.Host == "" || u.User != nil {
			return DomainConfig{}, fmt.Errorf("invalid domain %q", raw)
		}
		authority = u.Host
	} else {
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
		if slashIdx := strings.IndexByte(d, '/'); slashIdx >= 0 {
			d = d[:slashIdx]
		}
		authority = strings.TrimSpace(d)
	}
	if authority == "" || strings.ContainsAny(authority, " \t\r\n@") {
		return DomainConfig{}, fmt.Errorf("invalid domain %q", raw)
	}

	// Bracket bare IPv6 literals (e.g. "::1" -> "[::1]") before parsing as URL authority.
	if ip := net.ParseIP(authority); ip != nil && ip.To4() == nil {
		authority = "[" + authority + "]"
	}

	u, err := url.Parse("wss://" + authority)
	if err != nil || u.Host == "" || u.User != nil {
		return DomainConfig{}, fmt.Errorf("invalid domain %q", raw)
	}
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n/") {
		return DomainConfig{}, fmt.Errorf("invalid domain %q", raw)
	}

	port := u.Port()
	if port != "" {
		pNum, pErr := strconv.Atoi(port)
		if pErr != nil || pNum < 1 || pNum > 65535 {
			return DomainConfig{}, fmt.Errorf("invalid domain port %q in %q", port, raw)
		}
	}

	hostPort := hostname
	if strings.Contains(hostname, ":") {
		hostPort = "[" + hostname + "]"
	}
	if port != "" && port != "443" {
		hostPort = net.JoinHostPort(hostname, port)
	}
	return DomainConfig{
		HostPort: hostPort,
		Hostname: hostname,
	}, nil
}

// ResolveDomainFromEnv returns the normalized DomainConfig from LIGHTHOUSE_DOMAIN
// (or legacy LIGHTHOUSE_STUN_DOMAIN fallback) if set and valid.
func ResolveDomainFromEnv() (DomainConfig, bool) {
	for _, key := range []string{"LIGHTHOUSE_DOMAIN", "LIGHTHOUSE_STUN_DOMAIN"} {
		if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
			if cfg, err := NormalizeDomain(raw); err == nil {
				return cfg, true
			}
			return DomainConfig{}, false
		}
	}
	return DomainConfig{}, false
}

// DefaultHubOrigin resolves the default WSS hub origin for CLI help and startup defaults.
func DefaultHubOrigin() string {
	if origin := strings.TrimSpace(os.Getenv("LIGHTHOUSE_HUB_ORIGIN")); origin != "" {
		return origin
	}
	if dom, ok := ResolveDomainFromEnv(); ok {
		return dom.HubOrigin()
	}
	return "wss://localhost:8443"
}

// DefaultHubURL resolves the default WSS signaling URL for lighthouse-ui.
func DefaultHubURL() string {
	if hubURL := strings.TrimSpace(os.Getenv("LIGHTHOUSE_HUB_URL")); hubURL != "" {
		return hubURL
	}
	if dom, ok := ResolveDomainFromEnv(); ok {
		return dom.HubURL()
	}
	return "wss://localhost:8443/v1/signal"
}

// DefaultTURNAdvertiseHost resolves the default advertised relay host from LIGHTHOUSE_DOMAIN.
func DefaultTURNAdvertiseHost() string {
	if host := strings.TrimSpace(os.Getenv("LIGHTHOUSE_TURN_ADVERTISE_HOST")); host != "" {
		return host
	}
	if dom, ok := ResolveDomainFromEnv(); ok {
		return dom.Hostname
	}
	return ""
}

// DefaultTURNRealm resolves the default TURN authentication realm from LIGHTHOUSE_DOMAIN.
func DefaultTURNRealm(fallback string) string {
	if realm := strings.TrimSpace(os.Getenv("LIGHTHOUSE_TURN_REALM")); realm != "" {
		return realm
	}
	if dom, ok := ResolveDomainFromEnv(); ok {
		return dom.Hostname
	}
	return fallback
}
