package cli_test

import (
	"os"
	"path/filepath"
	"testing"

	"lighthouse-in-snoo/internal/cli"
)

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw          string
		wantHostPort string
		wantHost     string
		wantOrigin   string
		wantURL      string
	}{
		{
			raw:          "hub.example.com",
			wantHostPort: "hub.example.com",
			wantHost:     "hub.example.com",
			wantOrigin:   "wss://hub.example.com",
			wantURL:      "wss://hub.example.com/v1/signal",
		},
		{
			raw:          "HUB.EXAMPLE.COM:443",
			wantHostPort: "hub.example.com",
			wantHost:     "hub.example.com",
			wantOrigin:   "wss://hub.example.com",
			wantURL:      "wss://hub.example.com/v1/signal",
		},
		{
			raw:          "hub.example.com:8443",
			wantHostPort: "hub.example.com:8443",
			wantHost:     "hub.example.com",
			wantOrigin:   "wss://hub.example.com:8443",
			wantURL:      "wss://hub.example.com:8443/v1/signal",
		},
		{
			raw:          "wss://hub.example.com:9443/v1/signal",
			wantHostPort: "hub.example.com:9443",
			wantHost:     "hub.example.com",
			wantOrigin:   "wss://hub.example.com:9443",
			wantURL:      "wss://hub.example.com:9443/v1/signal",
		},
		{
			raw:          "https://hub.example.com/",
			wantHostPort: "hub.example.com",
			wantHost:     "hub.example.com",
			wantOrigin:   "wss://hub.example.com",
			wantURL:      "wss://hub.example.com/v1/signal",
		},
		{
			raw:          "203.0.113.10:8443",
			wantHostPort: "203.0.113.10:8443",
			wantHost:     "203.0.113.10",
			wantOrigin:   "wss://203.0.113.10:8443",
			wantURL:      "wss://203.0.113.10:8443/v1/signal",
		},
		{
			raw:          "::1",
			wantHostPort: "[::1]",
			wantHost:     "::1",
			wantOrigin:   "wss://[::1]",
			wantURL:      "wss://[::1]/v1/signal",
		},
		{
			raw:          "[2001:db8::5]:8443",
			wantHostPort: "[2001:db8::5]:8443",
			wantHost:     "2001:db8::5",
			wantOrigin:   "wss://[2001:db8::5]:8443",
			wantURL:      "wss://[2001:db8::5]:8443/v1/signal",
		},
	}

	for _, tc := range cases {
		got, err := cli.NormalizeDomain(tc.raw)
		if err != nil {
			t.Fatalf("NormalizeDomain(%q) unexpected error: %v", tc.raw, err)
		}
		if got.HostPort != tc.wantHostPort || got.Hostname != tc.wantHost ||
			got.HubOrigin() != tc.wantOrigin || got.HubURL() != tc.wantURL {
			t.Fatalf("NormalizeDomain(%q) = %+v (origin=%q url=%q); want hostPort=%q host=%q origin=%q url=%q",
				tc.raw, got, got.HubOrigin(), got.HubURL(), tc.wantHostPort, tc.wantHost, tc.wantOrigin, tc.wantURL)
		}
	}

	for _, bad := range []string{"", "   ", "bad domain", "user@hub.example.com", "hub.example.com:99999", "hub.example.com:0", "://missing"} {
		if got, err := cli.NormalizeDomain(bad); err == nil {
			t.Fatalf("NormalizeDomain(%q) = %+v; expected error", bad, got)
		}
	}
}

func TestSingleDomainEnvResolutionAndOverrides(t *testing.T) {
	// Clear relevant LIGHTHOUSE_* and PaaS PORT variables for isolated env checks.
	for _, k := range []string{
		"PORT",
		"LIGHTHOUSE_HTTPS_ADDR",
		"LIGHTHOUSE_DOMAIN",
		"LIGHTHOUSE_STUN_DOMAIN",
		"LIGHTHOUSE_HUB_ORIGIN",
		"LIGHTHOUSE_HUB_URL",
		"LIGHTHOUSE_TURN_ADVERTISE_HOST",
		"LIGHTHOUSE_TURN_REALM",
	} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}

	// Defaults when nothing is set (hub origin empty => accept all domains/ports dynamically).
	if got := cli.DefaultHTTPSAddr(); got != ":8443" {
		t.Fatalf("DefaultHTTPSAddr() = %q; want :8443", got)
	}
	t.Setenv("PORT", "8080")
	if got := cli.DefaultHTTPSAddr(); got != ":8080" {
		t.Fatalf("DefaultHTTPSAddr() with PORT=8080 = %q; want :8080", got)
	}
	t.Setenv("PORT", ":9090")
	if got := cli.DefaultHTTPSAddr(); got != ":9090" {
		t.Fatalf("DefaultHTTPSAddr() with PORT=:9090 = %q; want :9090", got)
	}
	t.Setenv("PORT", "not-a-port")
	if got := cli.DefaultHTTPSAddr(); got != ":8443" {
		t.Fatalf("DefaultHTTPSAddr() with invalid PORT = %q; want :8443", got)
	}
	t.Setenv("PORT", "8080")
	t.Setenv("LIGHTHOUSE_HTTPS_ADDR", "127.0.0.1:9443")
	if got := cli.DefaultHTTPSAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("DefaultHTTPSAddr() with explicit LIGHTHOUSE_HTTPS_ADDR = %q; want 127.0.0.1:9443", got)
	}
	_ = os.Unsetenv("PORT")
	_ = os.Unsetenv("LIGHTHOUSE_HTTPS_ADDR")

	if got := cli.DefaultHubOrigin(); got != "" {
		t.Fatalf("DefaultHubOrigin() = %q; want empty (accept all)", got)
	}
	if got := cli.DefaultHubURL(); got != "localhost:8443" {
		t.Fatalf("DefaultHubURL() = %q; want localhost:8443", got)
	}
	if got := cli.DefaultTURNAdvertiseHost(); got != "" {
		t.Fatalf("DefaultTURNAdvertiseHost() = %q; want empty", got)
	}
	if got := cli.DefaultTURNRealm("lighthouse"); got != "lighthouse" {
		t.Fatalf("DefaultTURNRealm() = %q; want lighthouse", got)
	}

	// Load single LIGHTHOUSE_DOMAIN from .env file.
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("LIGHTHOUSE_DOMAIN=vpn.example.org:8443\nOTHER_VAR=ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli.LoadDotEnvIfPresent(envFile)

	if got := cli.DefaultHubOrigin(); got != "wss://vpn.example.org:8443" {
		t.Fatalf("DefaultHubOrigin() = %q; want wss://vpn.example.org:8443", got)
	}
	if got := cli.DefaultHubURL(); got != "vpn.example.org:8443" {
		t.Fatalf("DefaultHubURL() = %q; want vpn.example.org:8443", got)
	}
	if got := cli.DefaultTURNAdvertiseHost(); got != "vpn.example.org" {
		t.Fatalf("DefaultTURNAdvertiseHost() = %q; want vpn.example.org", got)
	}
	if got := cli.DefaultTURNRealm("lighthouse"); got != "vpn.example.org" {
		t.Fatalf("DefaultTURNRealm() = %q; want vpn.example.org", got)
	}

	// Explicit overrides take precedence over LIGHTHOUSE_DOMAIN.
	t.Setenv("LIGHTHOUSE_HUB_ORIGIN", "wss://custom-origin.example.org")
	t.Setenv("LIGHTHOUSE_HUB_URL", "wss://custom-ui.example.org/v1/signal")
	t.Setenv("LIGHTHOUSE_TURN_ADVERTISE_HOST", "relay.example.org")
	t.Setenv("LIGHTHOUSE_TURN_REALM", "custom-realm")
	if got := cli.DefaultHubOrigin(); got != "wss://custom-origin.example.org" {
		t.Fatalf("override DefaultHubOrigin() = %q", got)
	}
	if got := cli.DefaultHubURL(); got != "wss://custom-ui.example.org/v1/signal" {
		t.Fatalf("override DefaultHubURL() = %q", got)
	}
	if got := cli.DefaultTURNAdvertiseHost(); got != "relay.example.org" {
		t.Fatalf("override DefaultTURNAdvertiseHost() = %q", got)
	}
	if got := cli.DefaultTURNRealm("lighthouse"); got != "custom-realm" {
		t.Fatalf("override DefaultTURNRealm() = %q", got)
	}
}
