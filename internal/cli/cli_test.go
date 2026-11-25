package cli_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"lighthouse-in-snoo/internal/cli"
)

func buildTestApp(t *testing.T, gotOut *string, gotTTL *time.Duration, gotFlag *bool) *cli.Command {
	t.Helper()

	root := &cli.Command{
		Name:       "app",
		Version:    "0.1.0",
		ShortAbout: "Test CLI",
	}
	runCmd := &cli.Command{
		Name:       "run",
		ShortAbout: "Run sample command",
		LongAbout:  "Run sample command with detailed clap-like help.",
		Examples:   []string{"app run --out file.txt --ttl 5s"},
		Run:        func(_ *cli.Context) error { return nil },
	}
	runCmd.StringOpt(gotOut, cli.Option{
		Long:      "out-file",
		Short:     'o',
		ValueName: "PATH",
		ShortHelp: "Output path",
		LongHelp:  "Destination file path for output artifacts",
		EnvVar:    "APP_TEST_OUT",
		Required:  true,
	})
	runCmd.DurationOpt(gotTTL, cli.Option{
		Long:      "ttl",
		Short:     't',
		ValueName: "DURATION",
		ShortHelp: "Validity duration",
		Default:   "10s",
	})
	runCmd.BoolOpt(gotFlag, cli.Option{
		Long:      "gen-key",
		Short:     'g',
		ShortHelp: "Generate key if absent",
	})
	root.AddSubcommand(runCmd)
	return root
}

func TestSingleAndDoubleDashParsing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		args     []string
		wantOut  string
		wantTTL  time.Duration
		wantFlag bool
	}{
		{
			name:     "double dash separate values",
			args:     []string{"run", "--out-file", "a.txt", "--ttl", "30s", "--gen-key"},
			wantOut:  "a.txt",
			wantTTL:  30 * time.Second,
			wantFlag: true,
		},
		{
			name:     "single dash long flags",
			args:     []string{"run", "-out-file", "b.txt", "-ttl", "45s", "-gen-key"},
			wantOut:  "b.txt",
			wantTTL:  45 * time.Second,
			wantFlag: true,
		},
		{
			name:     "equals syntax with both dashes",
			args:     []string{"run", "--out-file=c.txt", "-ttl=15s", "--gen-key=false"},
			wantOut:  "c.txt",
			wantTTL:  15 * time.Second,
			wantFlag: false,
		},
		{
			name:     "short aliases with single and double dash",
			args:     []string{"run", "-o", "d.txt", "--t=20s", "-g"},
			wantOut:  "d.txt",
			wantTTL:  20 * time.Second,
			wantFlag: true,
		},
		{
			name:     "leading hyphen value like base64url peer_id",
			args:     []string{"run", "--out-file", "-AbCdEf12345"},
			wantOut:  "-AbCdEf12345",
			wantTTL:  10 * time.Second,
			wantFlag: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				out  string
				ttl  time.Duration
				flag bool
			)
			app := buildTestApp(t, &out, &ttl, &flag)
			var stdout, stderr bytes.Buffer
			if err := app.Execute(tc.args, &stdout, &stderr); err != nil {
				t.Fatalf("Execute(%v) failed: %v\nstderr: %s", tc.args, err, stderr.String())
			}
			if out != tc.wantOut || ttl != tc.wantTTL || flag != tc.wantFlag {
				t.Fatalf("got (%q, %v, %v); want (%q, %v, %v)", out, ttl, flag, tc.wantOut, tc.wantTTL, tc.wantFlag)
			}
		})
	}
}

func TestClapHelpAndDiagnostics(t *testing.T) {
	t.Parallel()

	t.Run("verbose help via --help and help subcommand", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{"run", "--help"}, {"run", "-help"}, {"help", "run"}} {
			var (
				out  string
				ttl  time.Duration
				flag bool
			)
			app := buildTestApp(t, &out, &ttl, &flag)
			var stdout, stderr bytes.Buffer
			if err := app.Execute(args, &stdout, &stderr); err != nil {
				t.Fatalf("Execute(%v) error: %v", args, err)
			}
			text := stdout.String()
			for _, want := range []string{
				"Usage: app run --out-file <PATH> [OPTIONS]",
				"-o, --out-file <PATH>",
				"[env: APP_TEST_OUT]",
				"[required]",
				"[default: 10s]",
				"Examples:",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("args=%v missing %q in help:\n%s", args, want, text)
				}
			}
		}
	})

	t.Run("compact help via -h", func(t *testing.T) {
		t.Parallel()
		var (
			out  string
			ttl  time.Duration
			flag bool
		)
		app := buildTestApp(t, &out, &ttl, &flag)
		var stdout, stderr bytes.Buffer
		if err := app.Execute([]string{"run", "-h"}, &stdout, &stderr); err != nil {
			t.Fatalf("Execute(-h) error: %v", err)
		}
		if !strings.Contains(stdout.String(), "see more with '--help'") {
			t.Fatalf("expected compact help hint, got:\n%s", stdout.String())
		}
	})

	t.Run("unknown flag suggestion and missing required flag", func(t *testing.T) {
		t.Parallel()
		var (
			out  string
			ttl  time.Duration
			flag bool
		)
		app := buildTestApp(t, &out, &ttl, &flag)
		var stdout, stderr bytes.Buffer
		err := app.Execute([]string{"run", "--out-fle", "x"}, &stdout, &stderr)
		var exitErr *cli.ExitError
		if !errors.As(err, &exitErr) || exitErr.Code != 2 {
			t.Fatalf("expected ExitError(2), got %v", err)
		}
		if !strings.Contains(stderr.String(), "tip: a similar argument exists: '--out-file'") {
			t.Fatalf("expected suggestion tip, got:\n%s", stderr.String())
		}

		stderr.Reset()
		err = app.Execute([]string{"run"}, &stdout, &stderr)
		if !errors.As(err, &exitErr) || exitErr.Code != 2 {
			t.Fatalf("expected ExitError(2) on missing required arg, got %v", err)
		}
		if !strings.Contains(stderr.String(), "--out-file <PATH>") {
			t.Fatalf("expected missing required flag message, got:\n%s", stderr.String())
		}
	})
}
