package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lighthouse-in-snoo/pkg/version"
)

func TestZeroConfigHubCLIAndVersionAlignment(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	hubBin := filepath.Join(tmpDir, "lighthouse")
	uiBin := filepath.Join(tmpDir, "lighthouse-ui")

	if out, err := exec.Command("go", "build", "-o", hubBin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build hub binary failed: %v\n%s", err, string(out))
	}
	uiArgs := []string{"build"}
	if exec.Command("pkg-config", "--exists", "xxf86vm").Run() != nil {
		uiArgs = append(uiArgs, "-tags", "wayland")
	}
	uiArgs = append(uiArgs, "-o", uiBin, "../lighthouse-ui")
	if out, err := exec.Command("go", uiArgs...).CombinedOutput(); err != nil {
		t.Fatalf("build ui binary failed: %v\n%s", err, string(out))
	}

	// Root --help and -V version check.
	helpOut, err := exec.Command(hubBin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse --help failed: %v\n%s", err, string(helpOut))
	}
	for _, want := range []string{"Usage: lighthouse <COMMAND>", "Commands:", "hub", "Options:", "-h, --help", "-V, --version"} {
		if !strings.Contains(string(helpOut), want) {
			t.Fatalf("root --help missing %q:\n%s", want, string(helpOut))
		}
	}
	// Removed subcommands (admin, peer) must not appear in hub CLI help.
	for _, removed := range []string{"\n  admin", "\n  peer"} {
		if strings.Contains(string(helpOut), removed) {
			t.Fatalf("root --help still lists removed subcommand %q:\n%s", removed, string(helpOut))
		}
	}

	verOut, err := exec.Command(hubBin, "-V").CombinedOutput()
	wantHubVer := "lighthouse " + version.Version
	if err != nil || strings.TrimSpace(string(verOut)) != wantHubVer {
		t.Fatalf("lighthouse -V = %q (err=%v); want %q", strings.TrimSpace(string(verOut)), err, wantHubVer)
	}

	uiVerOut, err := exec.Command(uiBin, "--version").CombinedOutput()
	wantUIVer := "lighthouse-ui " + version.Version
	if err != nil || strings.TrimSpace(string(uiVerOut)) != wantUIVer {
		t.Fatalf("lighthouse-ui --version = %q (err=%v); want %q", strings.TrimSpace(string(uiVerOut)), err, wantUIVer)
	}

	uiHelpOut, err := exec.Command(uiBin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse-ui --help failed: %v\n%s", err, string(uiHelpOut))
	}
	for _, want := range []string{"--domain <DOMAIN>", "[env: LIGHTHOUSE_DOMAIN]", "--ifname <NAME>", "--hub <URL>", "--tcp-only", "--blacklist <PATH>"} {
		if !strings.Contains(string(uiHelpOut), want) {
			t.Fatalf("lighthouse-ui --help missing %q:\n%s", want, string(uiHelpOut))
		}
	}
	for _, removed := range []string{"--cidr", "--hub-passphrase", "LIGHTHOUSE_PASSPHRASE"} {
		if strings.Contains(string(uiHelpOut), removed) {
			t.Fatalf("lighthouse-ui --help must not expose %q:\n%s", removed, string(uiHelpOut))
		}
	}

	// Hub subcommand help: blinded universal hub with --domain, --cidr, --tls-algo & universal relay.
	hubHelp, err := exec.Command(hubBin, "help", "hub").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse help hub failed: %v\n%s", err, string(hubHelp))
	}
	for _, want := range []string{
		"Usage: lighthouse hub [OPTIONS]",
		"--domain <DOMAIN>",
		"[env: LIGHTHOUSE_DOMAIN]",
		"--https-addr <ADDR>",
		"[env: LIGHTHOUSE_HTTPS_ADDR]",
		"--stuns-addr <ADDR>",
		"--cidr <CIDR>",
		"[env: LIGHTHOUSE_CIDR]",
		"--tls-algo <ALGO>",
		"[env: LIGHTHOUSE_TLS_ALGO]",
		"--tls-rsa-bits <BITS>",
		"[env: LIGHTHOUSE_TLS_RSA_BITS]",
		"--no-relay",
		"--tcp-only",
		"[env: LIGHTHOUSE_TCP_ONLY]",
		"--insecure",
		"--turn-advertise-host <HOST>",
	} {
		if !strings.Contains(string(hubHelp), want) {
			t.Fatalf("hub help missing %q:\n%s", want, string(hubHelp))
		}
	}
	for _, removed := range []string{"--policy", "--sqlite", "--passphrase", "LIGHTHOUSE_PASSPHRASE", "LIGHTHOUSE_TLS_CERT", "LIGHTHOUSE_TLS_KEY"} {
		if strings.Contains(string(hubHelp), removed) {
			t.Fatalf("hub help must not include removed option %q:\n%s", removed, string(hubHelp))
		}
	}

	// Single-dash full-word flags rejected with exit code 2.
	for _, badArgs := range [][]string{
		{"-help"},
		{"hub", "-help"},
		{"hub", "-https-addr", ":8443"},
		{"hub", "-tls-algo", "ed25519"},
	} {
		cmd := exec.Command(hubBin, badArgs...)
		out, err := cmd.CombinedOutput()
		if err == nil || cmd.ProcessState.ExitCode() != 2 {
			t.Fatalf("expected exit code 2 for %v, got err=%v code=%d out=%s", badArgs, err, cmd.ProcessState.ExitCode(), string(out))
		}
		if !strings.Contains(string(out), "use two dashes") {
			t.Fatalf("expected double-dash tip for %v, got:\n%s", badArgs, string(out))
		}
	}

	// Plaintext --stun-addr without --insecure rejected with exit code 2.
	hubInsecureCmd := exec.Command(hubBin, "hub", "--stun-addr", ":3478")
	hubInsecureOut, hubInsecureErr := hubInsecureCmd.CombinedOutput()
	if hubInsecureErr == nil || hubInsecureCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for --stun-addr without --insecure, got err=%v code=%d out=%s", hubInsecureErr, hubInsecureCmd.ProcessState.ExitCode(), string(hubInsecureOut))
	}
	if !strings.Contains(string(hubInsecureOut), "--insecure") {
		t.Fatalf("expected --insecure hint:\n%s", string(hubInsecureOut))
	}

	// Invalid hub --domain, --cidr, and --tls-algo rejected with exit code 2.
	for _, badArgs := range [][]string{
		{"hub", "--domain", "bad domain name"},
		{"hub", "--domain", "hub.example.com:99999"},
		{"hub", "--cidr", "not-a-cidr"},
		{"hub", "--tls-algo", "ed448"},
		{"hub", "--tls-algo", "bogus"},
		{"hub", "--tls-algo", "ed25519", "--tls-rsa-bits", "2048"},
	} {
		badValCmd := exec.Command(hubBin, badArgs...)
		if out, err := badValCmd.CombinedOutput(); err == nil || badValCmd.ProcessState.ExitCode() != 2 {
			t.Fatalf("expected exit code 2 for %v, got err=%v code=%d out=%s", badArgs, err, badValCmd.ProcessState.ExitCode(), string(out))
		}
	}

	// Typo suggestion on unknown double-dash option.
	badCmd := exec.Command(hubBin, "hub", "--tls-alg", "ed25519")
	badOut, badErr := badCmd.CombinedOutput()
	if badErr == nil || badCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for unknown flag, got err=%v code=%d", badErr, badCmd.ProcessState.ExitCode())
	}
	if !strings.Contains(string(badOut), "tip: a similar argument exists: '--tls-algo'") {
		t.Fatalf("expected typo suggestion in stderr:\n%s", string(badOut))
	}
}

func TestSingleSourceVersionAndRuntimeEnvDefaults(t *testing.T) {
	t.Parallel()

	// Single source of truth is pkg/version/version.go (no duplicate root VERSION file).
	if _, err := os.Stat(filepath.Join("..", "..", "VERSION")); !os.IsNotExist(err) {
		t.Fatalf("duplicate root VERSION file must not exist, stat err=%v", err)
	}
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	if strings.Contains(string(readmeBytes), version.Version) {
		t.Fatalf("README.md must not hardcode specific version %q", version.Version)
	}

	// Build definitions never duplicate Version or bake LIGHTHOUSE_* variables at build time.
	for _, rel := range []string{"Dockerfile", "Makefile", "docker-compose.yml", filepath.Join(".github", "workflows", "build.yml")} {
		data, readErr := os.ReadFile(filepath.Join("..", "..", rel))
		if readErr != nil {
			t.Fatalf("read %s: %v", rel, readErr)
		}
		text := string(data)
		if strings.Contains(text, "LIGHTHOUSE_") {
			t.Fatalf("%s must not reference LIGHTHOUSE_* variables at build time", rel)
		}
		if strings.Contains(text, "ARG VERSION") || strings.Contains(text, "appVersion") || strings.Contains(text, version.Version) {
			t.Fatalf("%s must not hardcode or duplicate version %q", rel, version.Version)
		}
		if rel == "Dockerfile" {
			if !strings.Contains(text, "FROM debian:13-slim") {
				t.Fatalf("Dockerfile must use debian:13-slim as runner image")
			}
			if strings.Contains(text, "gcr.io/") {
				t.Fatalf("Dockerfile must not reference gcr.io images")
			}
		}
		if rel == filepath.Join(".github", "workflows", "build.yml") && !strings.Contains(text, "libwayland-dev") {
			t.Fatalf("%s must install libwayland-dev for Fyne v2.8 / GLFW v3.4 Linux headers", rel)
		}
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "lighthouse-ver")
	uiBinPath := filepath.Join(tmpDir, "lighthouse-ui-ver")
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("build binary failed: %v\n%s", err, string(out))
	}
	uiBuildArgs := []string{"build"}
	if exec.Command("pkg-config", "--exists", "xxf86vm").Run() != nil {
		uiBuildArgs = append(uiBuildArgs, "-tags", "wayland")
	}
	uiBuildArgs = append(uiBuildArgs, "-o", uiBinPath, "../lighthouse-ui")
	if out, err := exec.Command("go", uiBuildArgs...).CombinedOutput(); err != nil {
		t.Fatalf("build ui binary failed: %v\n%s", err, string(out))
	}

	// Verify single LIGHTHOUSE_DOMAIN in runtime .env auto-configures hub origin, TURN host/realm, and UI WSS URL.
	dotEnvDir := t.TempDir()
	dotEnvContent := strings.Join([]string{
		"# Single-domain runtime defaults",
		"LIGHTHOUSE_DOMAIN=hub.dotenv.example",
		"NON_LIGHTHOUSE_VAR=ignored",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dotEnvDir, ".env"), []byte(dotEnvContent), 0o600); err != nil {
		t.Fatal(err)
	}

	dotEnvCmd := exec.Command(binPath, "hub", "--help")
	dotEnvCmd.Dir = dotEnvDir
	dotEnvCmd.Env = stripLighthouseEnv(os.Environ())
	dotEnvHelp, err := dotEnvCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dotenv hub --help failed: %v\n%s", err, string(dotEnvHelp))
	}
	for _, want := range []string{
		"[default: wss://hub.dotenv.example]",
		"[default: hub.dotenv.example]",
	} {
		if !strings.Contains(string(dotEnvHelp), want) {
			t.Fatalf("dotenv hub --help missing auto-configured %q:\n%s", want, string(dotEnvHelp))
		}
	}

	uiDotEnvCmd := exec.Command(uiBinPath, "--help")
	uiDotEnvCmd.Dir = dotEnvDir
	uiDotEnvCmd.Env = stripLighthouseEnv(os.Environ())
	uiDotEnvHelp, err := uiDotEnvCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dotenv ui --help failed: %v\n%s", err, string(uiDotEnvHelp))
	}
	if !strings.Contains(string(uiDotEnvHelp), "[default: wss://hub.dotenv.example/v1/signal]") {
		t.Fatalf("dotenv ui --help missing auto-configured WSS URL:\n%s", string(uiDotEnvHelp))
	}

	// Explicit process ENV LIGHTHOUSE_DOMAIN (with port) overrides .env without rebuilding.
	envCmd := exec.Command(binPath, "hub", "--help")
	envCmd.Dir = dotEnvDir
	envCmd.Env = append(stripLighthouseEnv(os.Environ()), "LIGHTHOUSE_DOMAIN=hub.env.example:8443")
	envHelp, err := envCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("env hub --help failed: %v\n%s", err, string(envHelp))
	}
	for _, want := range []string{
		"[default: wss://hub.env.example:8443]",
		"[default: hub.env.example]",
	} {
		if !strings.Contains(string(envHelp), want) {
			t.Fatalf("runtime env override missing %q:\n%s", want, string(envHelp))
		}
	}

	// Explicit LIGHTHOUSE_HUB_ORIGIN still overrides LIGHTHOUSE_DOMAIN.
	overrideCmd := exec.Command(binPath, "hub", "--help")
	overrideCmd.Dir = dotEnvDir
	overrideCmd.Env = append(stripLighthouseEnv(os.Environ()), "LIGHTHOUSE_HUB_ORIGIN=wss://custom.override.example")
	overrideHelp, err := overrideCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("override hub --help failed: %v\n%s", err, string(overrideHelp))
	}
	if !strings.Contains(string(overrideHelp), "[default: wss://custom.override.example]") {
		t.Fatalf("explicit LIGHTHOUSE_HUB_ORIGIN override missing:\n%s", string(overrideHelp))
	}
}

func stripLighthouseEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "LIGHTHOUSE_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
