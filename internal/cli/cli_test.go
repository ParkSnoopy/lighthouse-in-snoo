package cli_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"lighthouse-in-snoo/internal/cli"
)

type testState struct {
	out   string
	ttl   time.Duration
	flagA bool
	flagL bool
	flagG bool
	alh   bool
}

func buildTestApp(t *testing.T, st *testState) *cli.Command {
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
		Examples:   []string{"app run --out-file file.txt --ttl 5s"},
		Run:        func(_ *cli.Context) error { return nil },
	}
	runCmd.StringOpt(&st.out, cli.Option{
		Long:      "out-file",
		Short:     'o',
		ValueName: "PATH",
		ShortHelp: "Output path",
		LongHelp:  "Destination file path for output artifacts",
		EnvVar:    "APP_TEST_OUT",
		Required:  true,
	})
	runCmd.DurationOpt(&st.ttl, cli.Option{
		Long:      "ttl",
		Short:     't',
		ValueName: "DURATION",
		ShortHelp: "Validity duration",
		Default:   "10s",
	})
	runCmd.BoolOpt(&st.flagA, cli.Option{
		Long:      "all",
		Short:     'a',
		ShortHelp: "All entries",
	})
	runCmd.BoolOpt(&st.flagL, cli.Option{
		Long:      "long",
		Short:     'l',
		ShortHelp: "Long listing",
	})
	runCmd.BoolOpt(&st.flagG, cli.Option{
		Long:      "gen-key",
		Short:     'g',
		ShortHelp: "Generate key if absent",
	})
	runCmd.BoolOpt(&st.alh, cli.Option{
		Long:      "alh",
		ShortHelp: "Full-word flag named alh (must require --alh)",
	})
	root.AddSubcommand(runCmd)
	return root
}

func TestStrictPOSIXAndClapFlagParsing(t *testing.T) {
	t.Parallel()

	t.Run("double dash long flags and equals syntax", func(t *testing.T) {
		t.Parallel()
		var st testState
		app := buildTestApp(t, &st)
		var stdout, stderr bytes.Buffer
		args := []string{"run", "--out-file=a.txt", "--ttl", "30s", "--gen-key", "--alh"}
		if err := app.Execute(args, &stdout, &stderr); err != nil {
			t.Fatalf("Execute(%v) failed: %v\nstderr: %s", args, err, stderr.String())
		}
		if st.out != "a.txt" || st.ttl != 30*time.Second || !st.flagG || !st.alh || st.flagA || st.flagL {
			t.Fatalf("unexpected state: %+v", st)
		}
	})

	t.Run("concatenated short flags like ls -al and trailing value -algO", func(t *testing.T) {
		t.Parallel()
		var st testState
		app := buildTestApp(t, &st)
		var stdout, stderr bytes.Buffer
		args := []string{"run", "-algo", "clustered.txt", "-t25s"}
		if err := app.Execute(args, &stdout, &stderr); err != nil {
			t.Fatalf("Execute(%v) failed: %v\nstderr: %s", args, err, stderr.String())
		}
		if !st.flagA || !st.flagL || !st.flagG || st.alh || st.out != "clustered.txt" || st.ttl != 25*time.Second {
			t.Fatalf("unexpected state: %+v", st)
		}
	})

	t.Run("-alh triggers short cluster a+l+h (help) and NEVER --alh", func(t *testing.T) {
		t.Parallel()
		var st testState
		app := buildTestApp(t, &st)
		var stdout, stderr bytes.Buffer
		if err := app.Execute([]string{"run", "-alh"}, &stdout, &stderr); err != nil {
			t.Fatalf("Execute(-alh) failed: %v\nstderr: %s", err, stderr.String())
		}
		if st.alh {
			t.Fatal("-alh MUST NOT set --alh")
		}
		if !strings.Contains(stdout.String(), "Usage: app run") {
			t.Fatalf("expected -alh to trigger compact -h help, got:\n%s", stdout.String())
		}
	})

	t.Run("leading hyphen value like base64url peer_id", func(t *testing.T) {
		t.Parallel()
		var st testState
		app := buildTestApp(t, &st)
		var stdout, stderr bytes.Buffer
		if err := app.Execute([]string{"run", "--out-file", "-AbCdEf12345"}, &stdout, &stderr); err != nil {
			t.Fatalf("Execute failed: %v", err)
		}
		if st.out != "-AbCdEf12345" {
			t.Fatalf("got %q, want -AbCdEf12345", st.out)
		}
	})

	t.Run("reject single-dash full-word flags and double-dash single-char aliases", func(t *testing.T) {
		t.Parallel()
		rejected := []struct {
			args    []string
			wantTip string
		}{
			{[]string{"run", "-help"}, "use two dashes: '--help'"},
			{[]string{"-help"}, "use two dashes: '--help'"},
			{[]string{"-version"}, "use two dashes: '--version'"},
			{[]string{"run", "-gen-key", "-o", "x"}, "use two dashes: '--gen-key'"},
			{[]string{"run", "--h"}, "'-h' or '--help'"},
			{[]string{"run", "--o", "x"}, "'-o' or '--out-file'"},
			{[]string{"--h"}, "'-h' or '--help'"},
			{[]string{"--V"}, "'-V' or '--version'"},
		}
		for _, tc := range rejected {
			var st testState
			app := buildTestApp(t, &st)
			var stdout, stderr bytes.Buffer
			err := app.Execute(tc.args, &stdout, &stderr)
			var exitErr *cli.ExitError
			if !errors.As(err, &exitErr) || exitErr.Code != 2 {
				t.Errorf("args=%v: expected ExitError(2), got %v", tc.args, err)
				continue
			}
			if !strings.Contains(stderr.String(), tc.wantTip) {
				t.Errorf("args=%v: expected tip %q in stderr:\n%s", tc.args, tc.wantTip, stderr.String())
			}
		}
	})
}

func TestClapHelpAndDiagnostics(t *testing.T) {
	t.Parallel()

	t.Run("verbose help via --help and help subcommand", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{"run", "--help"}, {"help", "run"}} {
			var st testState
			app := buildTestApp(t, &st)
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
		var st testState
		app := buildTestApp(t, &st)
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
		var st testState
		app := buildTestApp(t, &st)
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
