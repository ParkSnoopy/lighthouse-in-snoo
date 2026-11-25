# Hub signaling, universal relay, and security

The blinded zero-config universal hub runs without hub passphrases, static ACLs, or policy files, enforces TLS 1.3 on HTTPS/WSS, enables an integrated DTLS 1.3 / UDP STUNS + TURNS relay by default, generates TLS 1.3 certs by algorithm (`--tls-algo`), prunes empty passphrase rooms on peer expiry, blocks plaintext `--stun-addr` without `--insecure`, and resolves `LIGHTHOUSE_*` variables strictly at runtime.

## Sub-features

- `hub-tls13-only` serves `GET /healthz` over TLS 1.3 and rejects TLS 1.2 clients.
- `hub-universal-relay` enables integrated DTLS 1.3 / UDP STUNS + TURNS relay (`"relay_active":true`) on `--stuns-addr` without static config.
- `hub-autotls-algo` starts with zero certificate files using `--tls-algo` (`ed25519` default, plus `nistp-256`, `nistp-384`, `nistp-521`, `rsa`).
- `hub-insecure-gate` rejects `--stun-addr` without `--insecure` (exit code `2`) and binds plaintext UDP only when `--insecure` is set.
- `hub-version-and-env` aligns `lighthouse --version` and `lighthouse-ui --version` with `pkg/version/version.go` and reads `LIGHTHOUSE_*` from `.env` and process env at runtime.

## How to get to it (user POV)

- Run `lighthouse hub` (default Ed25519 AutoTLS) or `lighthouse hub --tls-algo nistp-256`.
- Query `GET https://<host>:<port>/healthz`.
- Run `lighthouse --version`, `lighthouse-ui --version`, and `lighthouse hub --help` with runtime `LIGHTHOUSE_*` env vars or a local `.env` file.

## Driving it with control-lighthouse

Preconditions:

- Default run is launched (`"$CTRL" launch --run-id hub-sec`) and `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.

- **Confirm TLS 1.3 healthy, TLS 1.2 rejected, and universal relay active.** Run `mkdir -p "$EVIDENCE_DIR/hub-security" && "$CTRL" doctor --run-dir "$RUN_DIR" > "$EVIDENCE_DIR/hub-security/doctor.json"`. JSON reports `"healthy": true`, `"tls12_rejected": true`, `"hub_udp_sockets": 1`, and matching `version` == `ui_version`. Confirm `grep -q '"relay_active":true' "$RUN_DIR/logs/hub.log"`.
- **Confirm plaintext `--stun-addr` rejected without `--insecure`.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "hub-security/reject-plain-hub.txt" -- hub --stun-addr 127.0.0.1:0 || true`. Captured `exit_code: 2` and stderr names `--insecure`.
- **Confirm single-dash full-word flag rejected.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "hub-security/bad-flag.txt" -- hub -https-addr :8443 || true`. Captured `exit_code: 2` and stderr advises using two dashes (`--`).
- **Confirm AutoTLS algorithm selection.** Launch `ALGO_STATE="$("$CTRL" launch --run-id hub-algo --auto-tls --tls-algo nistp-256)"`, extract `ALGO_DIR="$(jq -r '.run_dir' <<<"$ALGO_STATE")"`, run `"$CTRL" doctor --run-dir "$ALGO_DIR" > "$EVIDENCE_DIR/hub-security/algo-doctor.json"`, verify `"tls_algo":"nistp-256"` and `"auto_tls":true` in `"$ALGO_DIR/logs/hub.log"`, then run `"$CTRL" cleanup --run-dir "$ALGO_DIR"`.
- **Confirm opt-in `--insecure` hub binds both encrypted and plaintext UDP.** Launch `INSEC_STATE="$("$CTRL" launch --run-id hub-insec --insecure)"`, extract `INSEC_DIR="$(jq -r '.run_dir' <<<"$INSEC_STATE")"`, run `"$CTRL" doctor --run-dir "$INSEC_DIR" > "$EVIDENCE_DIR/hub-security/insecure-doctor.json"`, verify `"hub_udp_sockets": 2`, then run `"$CTRL" cleanup --run-dir "$INSEC_DIR"`.
- **Confirm runtime `.env` single-domain auto-config and env override.** Write `LIGHTHOUSE_DOMAIN=hub.verify.local` into `$RUN_DIR/dotenv-test/.env`, run `(cd "$RUN_DIR/dotenv-test" && env -u LIGHTHOUSE_DOMAIN -u LIGHTHOUSE_HUB_ORIGIN "$RUN_DIR/bin/lighthouse" hub --help)` and verify `[default: wss://hub.verify.local]` and `[default: hub.verify.local]`; then pass `LIGHTHOUSE_DOMAIN=hub.override.local` and verify override without rebuilding.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "hub-security" --note "Blinded universal hub, TLS 1.3, AutoTLS algorithm, runtime env"`.

## Gotchas

- `lighthouse` automatically loads `./.env` from its current working directory; `control-lighthouse` always runs inside `$RUN_DIR` with `LIGHTHOUSE_*` unset to prevent repo `.env` leakage.
- Only use `-k` with `curl` on `--auto-tls` runs; non-AutoTLS runs must validate against `--cacert "$RUN_DIR/tls/ca.crt"`.
- Always clean up secondary runs (`ALGO_DIR`, `INSEC_DIR`) immediately so ports and processes are not stranded.
