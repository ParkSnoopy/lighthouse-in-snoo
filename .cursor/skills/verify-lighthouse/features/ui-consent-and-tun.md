# Fyne UI, passphrase broadcast, explicit consent, and TUN routing

The Fyne desktop application (`lighthouse-ui`) binds a local OS TUN virtual network interface (`lh0`, hub-assigned CIDR default `10.88.0.0/16`), isolates peer discovery and connections strictly by offline passphrase room, gates every incoming connection behind an explicit Allow / Deny / Blacklist prompt, auto-adopts the hub's universal relay when behind restrictive NATs, and enforces cryptographic source-IP anti-spoofing on TUN packets.

## Sub-features

- `ui-binary-cli` compiles `lighthouse-ui` with single-source version alignment and `--ifname`, `--hub`, `--blacklist`, and `--tcp-only` options.
- `ui-consent-modal` prompts with verified peer ID, key algorithm, virtual IP, and DTLS fingerprint and enforces explicit Allow, Deny, and Blacklist actions.
- `broadcast-passphrase-scope` restricts peer discovery and AEAD-sealed peer labels strictly to peers sharing the exact offline passphrase.
- `tun-routing-antispoof` routes bidirectional IPv4 packets across authorized DTLS 1.3 tunnels and drops spoofed-source or unrouted packets.
- `universal-relay-auto` auto-provisions DTLS 1.3 / UDP TURNS credentials from a zero-config hub to bridge symmetric NATs without manual TURN configuration.

## How to get to it (user POV)

- Run `lighthouse-ui --hub wss://hub.example.com/v1/signal --ifname lh0`.
- Click **Bind & Connect**, enter a passphrase, click **Join** / toggle **Broadcast**, click **Connect**, and respond **Allow**, **Deny**, or **Blacklist** on the modal dialog.

## Driving it with control-lighthouse

Preconditions:

- Default run is launched (`"$CTRL" launch --run-id ui-tun`) and `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.

- **Confirm `lighthouse-ui` version and CLI flags.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --bin ui --capture "ui-tun/ui-version.txt" -- --version` and `"$CTRL" cli --run-dir "$RUN_DIR" --bin ui --capture "ui-tun/ui-help.txt" -- --help`. Version matches `pkg/version/version.go` and help lists `--ifname`, `--hub`, `--blacklist`, and `--tcp-only`.
- **Confirm headless Fyne UI controller, TUN router, and anti-spoofing under `-race`.** Run `mkdir -p "$EVIDENCE_DIR/ui-tun" && go test -race -v ./internal/ui ./pkg/tun > "$EVIDENCE_DIR/ui-tun/ui-tun-tests.txt"`. Exit code `0`, zero data races.
- **Confirm passphrase broadcast isolation, explicit consent, universal relay, and blinded room reaping under `-race`.** Run `go test -race -v ./test/acceptance -run 'TestPassphraseBroadcastIsolationAndUserConsent|TestUniversalPublicRelayAutoProvisionedAcrossSymmetricNATs|TestBlindedHubRoomIsolationAndEmptyRoomReaping' > "$EVIDENCE_DIR/ui-tun/acceptance.txt"`. Exit code `0`.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "ui-tun" --note "Fyne UI binary + headless consent/TUN/broadcast/universal relay proof"`.

## Gotchas

- Opening a real `/dev/net/tun` interface requires `CAP_NET_ADMIN` (or root) on Linux; unprivileged environments exercise the exact same `tun.Router` forwarding and anti-spoofing pipeline via `tun.MemoryDevice` and Fyne's `fyne.io/fyne/v2/test` headless driver.
- On Wayland-only Linux hosts without `libxxf86vm-dev`, `control-lighthouse` and `make build-ui` automatically build `lighthouse-ui` with `-tags wayland`.
