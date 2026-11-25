# Hub signaling, universal relay, and security

The zero-config universal hub runs statelessly with no ACLs or policy files, enforces TLS 1.3 on HTTPS/WSS, enables an integrated DTLS 1.3 / UDP STUNS + TURNS relay by default, supports optional offline passphrase gating (`--passphrase`) and ephemeral AutoTLS, blocks plaintext `--stun-addr` without `--insecure`, and resolves `LIGHTHOUSE_*` variables strictly at runtime.

## Sub-features

- `hub-tls13-only` serves `GET /healthz` over TLS 1.3 and rejects TLS 1.2 clients.
- `hub-universal-relay` enables integrated DTLS 1.3 / UDP STUNS + TURNS relay (`"relay_active":true`) on `--stuns-addr` without static config.
- `hub-autotls-zero-config` starts with zero flags or certificate files using an ephemeral self-signed TLS 1.3 certificate.
- `hub-passphrase-gate` enables offline shared passphrase gating (`"passphrase_gated":true`) without logging the raw passphrase.
- `hub-insecure-gate` rejects `--stun-addr` without `--insecure` (exit code `2`) and binds plaintext UDP only when `--insecure` is set.
- `hub-version-and-env` aligns `lighthouse --version` and `lighthouse-ui --version` with `pkg/version/version.go` and reads `LIGHTHOUSE_*` from `.env` and process env at runtime.

## How to get to it (user POV)

- Run `lighthouse hub` (zero-config AutoTLS) or `lighthouse hub --tls-cert <CERT> --tls-key <KEY> [--passphrase <SECRET>]`.
- Query `GET https://<host>:<port>/healthz`.
- Run `lighthouse --version`, `lighthouse-ui --version`, and `lighthouse hub --help` with runtime `LIGHTHOUSE_*` env vars or a local `.env` file.

## Driving it with control-lighthouse

Preconditions:

- Default run is launched (`"$CTRL" launch --run-id hub-sec`) and `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.

- **Confirm TLS 1.3 healthy, TLS 1.2 rejected, and universal relay active.** Run `mkdir -p "$EVIDENCE_DIR/hub-security" && "$CTRL" doctor --run-dir "$RUN_DIR" > "$EVIDENCE_DIR/hub-security/doctor.json"`. JSON reports `"healthy": true`, `"tls12_rejected": true`, `"hub_udp_sockets": 1`, and matching `version` == `ui_version`. Confirm `grep -q '"relay_active":true' "$RUN_DIR/logs/hub.log"`.
- **Confirm plaintext `--stun-addr` rejected without `--insecure`.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "hub-security/reject-plain-hub.txt" -- hub --stun-addr 127.0.0.1:0 || true`. Captured `exit_code: 2` and stderr names `--insecure`.
- **Confirm single-dash full-word flag rejected.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "hub-security/bad-flag.txt" -- hub -https-addr :8443 || true`. Captured `exit_code: 2` and stderr advises using two dashes (`--`).
- **Confirm zero-config AutoTLS + offline `--passphrase` hub.** Launch `PASS_STATE="$("$CTRL" launch --run-id hub-pass --auto-tls --passphrase "verify-offline-secret")"`, extract `PASS_DIR="$(jq -r '.run_dir' <<<"$PASS_STATE")"`, run `"$CTRL" doctor --run-dir "$PASS_DIR" > "$EVIDENCE_DIR/hub-security/pass-doctor.json"`, verify `"passphrase_gated":true` and `"auto_tls":true` in `"$PASS_DIR/logs/hub.log"` AND verify `! grep -q 'verify-offline-secret' "$PASS_DIR/logs/hub.log"`, then run `"$CTRL" cleanup --run-dir "$PASS_DIR"`.
- **Confirm opt-in `--insecure` hub binds both encrypted and plaintext UDP.** Launch `INSEC_STATE="$("$CTRL" launch --run-id hub-insec --insecure)"`, extract `INSEC_DIR="$(jq -r '.run_dir' <<<"$INSEC_STATE")"`, run `"$CTRL" doctor --run-dir "$INSEC_DIR" > "$EVIDENCE_DIR/hub-security/insecure-doctor.json"`, verify `"hub_udp_sockets": 2`, then run `"$CTRL" cleanup --run-dir "$INSEC_DIR"`.
- **Confirm runtime `.env` and env override.** Write `LIGHTHOUSE_HUB_ORIGIN=wss://hub.verify.local` into `$RUN_DIR/dotenv-test/.env`, run `(cd "$RUN_DIR/dotenv-test" && env -u LIGHTHOUSE_HUB_ORIGIN "$RUN_DIR/bin/lighthouse" hub --help)` and verify `[default: wss://hub.verify.local]`; then pass `LIGHTHOUSE_HUB_ORIGIN=wss://hub.override.local` and verify override without rebuilding.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "hub-security" --note "Zero-config universal hub, TLS 1.3, AutoTLS, passphrase gate, runtime env"`.

## Gotchas

- `lighthouse` automatically loads `./.env` from its current working directory; `control-lighthouse` always runs inside `$RUN_DIR` with `LIGHTHOUSE_*` unset to prevent repo `.env` leakage.
- Only use `-k` with `curl` on `--auto-tls` runs; non-AutoTLS runs must validate against `--cacert "$RUN_DIR/tls/ca.crt"`.
- Always clean up secondary runs (`PASS_DIR`, `INSEC_DIR`) immediately so ports and processes are not stranded.
