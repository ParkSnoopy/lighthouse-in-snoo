---
name: verify-lighthouse
description: Verify Lighthouse end to end by building the real `lighthouse` static hub binary and `lighthouse-ui` Fyne TUN app, launching isolated zero-config / passphrase-gated / `--tcp-only` / `--insecure` hubs, inspecting live sockets and TLS 1.3 enforcement, exercising Fyne UI + TUN + broadcast consent flows, capturing proof artifacts, and tearing down cleanly. Use when proving behavior after changes to hub signaling, universal relay, passphrase broadcasts, explicit consent, TUN routing, or CLI flags.
---

# Verify Lighthouse

Drive the real compiled `lighthouse` (`cmd/lighthouse`) and `lighthouse-ui` (`cmd/lighthouse-ui`) binaries against isolated local `lighthouse hub` instances, real kernel sockets, and real headless Fyne + TUN router suites. Never use shared production ports or host `LIGHTHOUSE_*` environment variables.

Primary surfaces: `lighthouse hub` CLI (`cmd/lighthouse`) and `lighthouse-ui` Fyne desktop TUN app (`cmd/lighthouse-ui`, `internal/ui`, `pkg/tun`). Secondary surface: `linux/amd64` container image (`Dockerfile`, `docker-compose.yml`).

Feature recipes live in [`features/README.md`](./features/README.md). Read the index and matching feature file before driving.

## Launch

Every run creates two disjoint directories:
- Disposable run dir: `/tmp/lighthouse-verify-<RUN_ID>` (built `lighthouse` and `lighthouse-ui` binaries, optional verification TLS CA/cert scaffolding, PID files, live logs).
- Durable evidence dir: `/tmp/lighthouse-verify-evidence/<RUN_ID>` (survives cleanup).

Launch builds the static `linux/amd64` hub binary (`CGO_ENABLED=0 GOARCH=amd64`) and the `lighthouse-ui` desktop binary, allocates unused local ports, and starts `lighthouse hub` with all `LIGHTHOUSE_*` env vars stripped.

```bash
CTRL=".cursor/skills/verify-lighthouse/scripts/control-lighthouse"
STATE="$("$CTRL" launch --run-id demo)"
RUN_DIR="$(jq -r '.run_dir' <<<"$STATE")"
EVIDENCE_DIR="$(jq -r '.evidence_dir' <<<"$STATE")"
```

Mode variants (each isolated in its own `--run-id`, safe to run side by side):
- Default zero-config universal relay (TLS 1.3 WSS + DTLS 1.3/UDP STUNS+TURNS): `"$CTRL" launch --run-id udp-run`
- Ephemeral AutoTLS (zero cert/key files): `"$CTRL" launch --run-id autotls-run --auto-tls`
- Offline passphrase-gated hub: `"$CTRL" launch --run-id pass-run --passphrase "offline-secret"`
- TCP-only (zero UDP, TLS 1.3/TCP STUNS): `"$CTRL" launch --run-id tcp-run --tcp-only`
- Opt-in insecure plaintext STUN/TURN alongside encrypted STUNS/TURNS: `"$CTRL" launch --run-id insecure-run --insecure`
- Relay disabled (STUNS Binding only): `"$CTRL" launch --run-id norelay-run --no-relay`

Readiness criteria enforced by `launch`:
1. Hub stderr JSON log contains `"msg":"lighthouse hub started"`.
2. `curl --tlsv1.3 --tls-max 1.3` against `GET /healthz` returns exact body `{"status":"ok"}`.

Teardown: always run `"$CTRL" cleanup --run-dir "$RUN_DIR"` when finished or after any failure.

## Doctor

Run this read-only check before driving any feature and whenever anything looks off:

```bash
"$CTRL" doctor --run-dir "$RUN_DIR"
```

`doctor` returns exit code `0` and `"healthy": true` only when all of the following hold:
- Tracked Hub PID is alive and its `/proc/<pid>/cmdline` matches `$RUN_DIR/bin/lighthouse`.
- Both `lighthouse --version` and `lighthouse-ui --version` match `const Version` in `pkg/version/version.go`.
- `ss` confirms our Hub PID owns the expected `https_port` (TCP) and `stuns_port` (UDP in default mode; TCP with zero UDP sockets in `--tcp-only` mode).
- TLS 1.3 `GET /healthz` returns `{"status":"ok"}` and TLS 1.2 `GET /healthz` fails the handshake.

If `doctor` returns non-zero, do not drive that instance; inspect `$RUN_DIR/logs/hub.log`, run `cleanup`, and relaunch.

## Drive

Always drive through `control-lighthouse` so every invocation uses the run's isolated binaries, stripped `LIGHTHOUSE_*` env, and tracked PIDs:

- **One-shot hub CLI checks** (`--help`, `-V`, negative flag checks):
  ```bash
  "$CTRL" cli --run-dir "$RUN_DIR" --capture "hub/help.txt" -- hub --help
  ```
- **One-shot UI CLI checks** (`--version`, `--help`, flag validation):
  ```bash
  "$CTRL" cli --run-dir "$RUN_DIR" --bin ui --capture "ui/version.txt" -- --version
  ```
- **Headless Fyne UI, TUN routing, universal relay, and passphrase consent proof**:
  ```bash
  go test -race -v ./internal/ui ./pkg/tun ./test/acceptance -run 'TestFyneController|TestRouterBidirectional|TestPassphraseBroadcast|TestUniversalPublicRelay|TestHubOfflinePassphrase'
  ```

Follow the exact recipes in [`features/`](./features/README.md) for preconditions, commands, and gotchas.

## Evidence

Proof artifacts are written to `/tmp/lighthouse-verify-evidence/<RUN_ID>/<feature>/` (outside `$RUN_DIR`) via:

```bash
"$CTRL" capture --run-dir "$RUN_DIR" --feature "<feature-id>" --note "<summary>"
```

Proof standards:
- Exercise the real compiled `lighthouse` and `lighthouse-ui` binaries and live network sockets.
- Capture both the action and resulting state: CLI transcripts (`command`, `exit_code`, `stdout`, `stderr`), hub JSON logs (`hub.log`), `state.json`, and `sockets.txt` (`ss -H -lntup` filtered strictly to our run PIDs).
- Verify observable side effects: `"relay_active":true` in `hub.log`, `"passphrase_gated":true` when `--passphrase` is set, zero UDP sockets in `sockets.txt` for `--tcp-only`, and single-source version alignment across both binaries.
- Verify privacy invariants: no raw passphrases, private keys, SDP, or ICE passwords appear in `hub.log`.

## Cleanup

Tear down every run (including failed runs) with:

```bash
"$CTRL" cleanup --run-dir "$RUN_DIR"
```

Cleanup rules:
- Kills ONLY the exact PIDs recorded in `$RUN_DIR/pids/` with `SIGTERM`, falling back to `SIGKILL` after 3s. Never kills by process name (`pkill`/`killall`).
- Deletes `$RUN_DIR` completely (including verification TLS scaffolding and built run binaries).
- Never deletes `$EVIDENCE_DIR`. Confirm evidence still exists under `/tmp/lighthouse-verify-evidence/<RUN_ID>/` after cleanup.

## Helpers

| Script | Invocation | Purpose |
| --- | --- | --- |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse launch [--run-id ID] [--passphrase S] [--tcp-only] [--insecure] [--no-relay] [--auto-tls]` | Build `lighthouse` + `lighthouse-ui`, start isolated zero-config hub, wait for readiness |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse doctor --run-dir DIR` | Read-only check of Hub PID, version alignment, socket ownership, and TLS 1.3 vs 1.2 |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse cli --run-dir DIR [--bin hub\|ui] [--capture REL] -- <args...>` | Run isolated CLI command and capture transcript + exit code |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse capture --run-dir DIR --feature ID [--note TEXT]` | Persist logs, state, and run-owned sockets into `$EVIDENCE_DIR/<ID>/` |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse cleanup --run-dir DIR` | Stop tracked PIDs and delete `$RUN_DIR` while preserving `$EVIDENCE_DIR` |
