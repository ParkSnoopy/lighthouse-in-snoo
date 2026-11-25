package peer_test

import (
	"testing"

	"lighthouse-in-snoo/pkg/peer"
)

func TestNormalizeSignalingURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want string
	}{
		{
			raw:  "port-1-lighthouse-in-snoo-mww9nj4q7f3b635f.sel3.cloudtype.app",
			want: "wss://port-1-lighthouse-in-snoo-mww9nj4q7f3b635f.sel3.cloudtype.app/v1/signal",
		},
		{
			raw:  "hub.example.com",
			want: "wss://hub.example.com/v1/signal",
		},
		{
			raw:  "HUB.EXAMPLE.COM:443",
			want: "wss://hub.example.com/v1/signal",
		},
		{
			raw:  "hub.example.com:8443",
			want: "wss://hub.example.com:8443/v1/signal",
		},
		{
			raw:  "localhost:8443",
			want: "wss://localhost:8443/v1/signal",
		},
		{
			raw:  "127.0.0.1:8443",
			want: "wss://127.0.0.1:8443/v1/signal",
		},
		{
			raw:  "::1",
			want: "wss://[::1]/v1/signal",
		},
		{
			raw:  "[::1]:8443",
			want: "wss://[::1]:8443/v1/signal",
		},
		{
			raw:  "https://hub.example.com",
			want: "wss://hub.example.com/v1/signal",
		},
		{
			raw:  "wss://hub.example.com/",
			want: "wss://hub.example.com/v1/signal",
		},
		{
			raw:  "wss://hub.example.com:8443/v1/signal",
			want: "wss://hub.example.com:8443/v1/signal",
		},
		{
			raw:  "hub.example.com/custom/ws",
			want: "wss://hub.example.com/custom/ws",
		},
	}

	for _, tc := range cases {
		got, err := peer.NormalizeSignalingURL(tc.raw)
		if err != nil {
			t.Fatalf("NormalizeSignalingURL(%q) unexpected error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeSignalingURL(%q) = %q; want %q", tc.raw, got, tc.want)
		}
	}

	for _, bad := range []string{
		"",
		"   ",
		"http://hub.example.com",
		"http://invalid-plain-hub",
		"ws://hub.example.com/v1/signal",
		"ftp://hub.example.com",
		"user@hub.example.com",
		"hub.example.com:99999",
		"hub.example.com:0",
	} {
		if got, err := peer.NormalizeSignalingURL(bad); err == nil {
			t.Fatalf("NormalizeSignalingURL(%q) = %q; expected error", bad, got)
		}
	}
}
