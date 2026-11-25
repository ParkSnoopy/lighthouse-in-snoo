# Lighthouse verification map

This directory is the maintained source for verifying the user-facing behavior of `lighthouse`. Read this index before driving the app, then follow the matching feature file.

## Baseline preconditions

- Set `CTRL=".cursor/skills/verify-lighthouse/scripts/control-lighthouse"`.
- Launch an isolated run with `"$CTRL" launch --run-id <RUN_ID>` so each run gets its own `/tmp/lighthouse-verify-<RUN_ID>`, free local ports, disposable TLS 1.3 CA/cert, and seeded `authority`, `peer-a`, and `peer-b` identities.
- Capture `RUN_DIR` and `EVIDENCE_DIR` from the JSON returned by `launch`.
- Run `"$CTRL" doctor --run-dir "$RUN_DIR"` and require `"healthy": true`.
- Never drive a hub or peer process that was not started by this verification run.

## Driving conventions

- Start every recipe from a fresh isolated launch unless its preconditions specify a mode flag (`--tcp-only`, `--insecure`, `--turn-secret`).
- Treat every command and flag as literal: full-word flags use `--`, single-char flags use `-` (and may cluster like `-gik`).
- Run one-shot commands through `"$CTRL" cli --run-dir "$RUN_DIR" -- ...` so host `LIGHTHOUSE_*` variables and `.env` never bleed into the run.
- Start live peers with `"$CTRL" peer-start` (which maintains an open stdin FIFO) and wait on real markers with `peer-wait`, never fixed sleeps.
- Always run `"$CTRL" cleanup --run-dir "$RUN_DIR"` after finishing or failing. Never remove `$EVIDENCE_DIR` during cleanup.

## Proof and skip reporting

- Capture both the action and the resulting state, not only final exit status.
- CLI proof captures the command, exit code, stdout, and stderr via `cli --capture`.
- Live session proof captures `hub.log`, `peer-*.out`, `peer-*.err`, `state.json`, `policy.json`, and `sockets.txt` via `capture --feature <ID>`.
- Mutation proof (SQLite ACL/revocation + `SIGHUP`) includes a live behavioral re-check against the running hub.
- Report any unreachable path with the attempted command and unmet precondition (for example, a container without a non-loopback UP IPv4 interface for `lighthouse peer` host candidates).
- Never claim a skipped entry point was verified through another path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior, followed by exactly four H2 sections in this order:

1. `Sub-features` lists short IDs with one line per behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with control-lighthouse` starts with `Preconditions:` and pairs each labeled step with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

## Features

- [Identity and membership management](./identity-and-membership.md) covers multi-algorithm `admin keygen`, `0600` key storage, `peer -gik` POSIX clustering, cross-algorithm `issue-membership`, and CLI flag validation.
- [Hub signaling and transport security](./hub-signaling-and-security.md) covers TLS 1.3 `/healthz`, TLS 1.2 rejection, DTLS 1.3 / UDP STUNS enforcement, `--insecure` gating, and runtime `.env`/`LIGHTHOUSE_*` loading.
- [Peer-to-peer messaging](./peer-to-peer-messaging.md) covers live WSS registration, DTLS 1.3 (`FEFC`) WebRTC establishment, bidirectional `data/v1` delivery, and log privacy.
- [Opt-in TCP-only mode](./tcp-only-mode.md) covers `--tcp-only` zero-UDP enforcement on hub and peers, TLS 1.3 / TCP STUNS, `?transport=udp` rejection, and live ICE-TCP + DTLS 1.3 messaging.
- [Policy reload and revocation](./policy-reload-and-revocation.md) covers `admin sqlite-acl`, `admin sqlite-revoke`, live `SIGHUP` reload, eviction of revoked peers, and rejection of re-registration.
