# Lighthouse verification map

This directory is the maintained source for verifying the user-facing behavior of `lighthouse` (zero-config universal hub + relay) and `lighthouse-ui` (Fyne desktop TUN interface app). Read this index before driving, then follow the matching feature file.

## Baseline preconditions

- Set `CTRL=".cursor/skills/verify-lighthouse/scripts/control-lighthouse"`.
- Launch an isolated run with `"$CTRL" launch --run-id <RUN_ID>` so each run gets its own `/tmp/lighthouse-verify-<RUN_ID>`, free local ports, and freshly compiled `lighthouse` and `lighthouse-ui` binaries.
- Capture `RUN_DIR` and `EVIDENCE_DIR` from the JSON returned by `launch`.
- Run `"$CTRL" doctor --run-dir "$RUN_DIR"` and require `"healthy": true`.
- Never drive a hub process that was not started by this verification run.

## Driving conventions

- Start every recipe from a fresh isolated launch matching its required mode flag (`--auto-tls`, `--passphrase`, `--tcp-only`, `--insecure`, `--no-relay`).
- Treat every command and flag as literal: full-word flags use `--`, single-char flags use `-`.
- Run one-shot commands through `"$CTRL" cli --run-dir "$RUN_DIR" [--bin hub|ui] -- ...` so host `LIGHTHOUSE_*` variables and `.env` never bleed into the run.
- Always run `"$CTRL" cleanup --run-dir "$RUN_DIR"` after finishing or failing. Never remove `$EVIDENCE_DIR` during cleanup.

## Proof and skip reporting

- Capture both the action and the resulting state, not only final exit status.
- CLI proof captures command, exit code, stdout, and stderr via `cli --capture`.
- Live hub proof captures `hub.log`, `hub.out`, `state.json`, and `sockets.txt` via `capture --feature <ID>`.
- Report any unreachable path with the attempted command and unmet precondition (for example, binding real `/dev/net/tun` without `CAP_NET_ADMIN` or launching a GUI display window without a display server).

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior, followed by four H2 sections in this order:

1. `Sub-features` lists short IDs with one line per behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with control-lighthouse` starts with `Preconditions:` and pairs each labeled step with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

## Features

- [Hub signaling, universal relay, and security](./hub-signaling-and-security.md) covers zero-config AutoTLS startup, TLS 1.3 `/healthz` and TLS 1.2 rejection, universal DTLS 1.3/UDP relay activation, `--passphrase` hub gating, `--insecure` gating, runtime `.env`/`LIGHTHOUSE_*` loading, and single-source version alignment.
- [Opt-in TCP-only mode](./tcp-only-mode.md) covers `--tcp-only` zero-UDP enforcement on `lighthouse hub`, TLS 1.3/TCP STUNS socket ownership, and live ICE-TCP + DTLS 1.3 acceptance checks.
- [Fyne UI, passphrase broadcast, explicit consent, and TUN routing](./ui-consent-and-tun.md) covers `lighthouse-ui` CLI/version checks, passphrase-scoped broadcast isolation, explicit Allow/Deny/Blacklist modal workflow, universal relay auto-provisioning, and TUN IPv4 routing with anti-spoofing.
