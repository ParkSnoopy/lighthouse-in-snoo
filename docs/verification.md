# Verification Procedures and Invariants

## 1. Build, Static Analysis, and Linting

Run all build, vet, dependency isolation, and `go-critic` checks from a fresh clone:

```bash
make lint
make build
make build-ui
```

`make lint` runs:

1. `go vet ./...`
2. `go tool gocritic check ./...` (standard profile across the entire repository)
3. `go tool gocritic check -enableAll ./pkg/identity/... ./pkg/protocol/... ./pkg/peer/... ./pkg/tun/... ./internal/hub/... ./internal/jcs/... ./internal/ratelimit/... ./internal/stunserver/... ./internal/turnserver/...` (maximum profile across all security-critical packages)

Verify dependency isolation:

```bash
go list -deps ./internal/hub | grep 'github\.com/pion/webrtc' && exit 1 || true
go list -deps ./internal/stunserver | grep -E 'github\.com/pion/(webrtc|turn)' && exit 1 || true
go list -deps ./cmd/lighthouse | grep -E 'fyne\.io/fyne|modernc\.org/sqlite' && exit 1 || true
```

### Verifiable Build Invariants

- `cmd/lighthouse` builds into a static `linux/amd64` binary (`CGO_ENABLED=0`) with zero Fyne or SQLite dependencies.
- `cmd/lighthouse-ui` builds the Fyne desktop TUN interface application and reports the exact same single-source version (`pkg/version/version.go`) as `cmd/lighthouse`.
- `internal/hub` never depends on `github.com/pion/webrtc`, and `internal/stunserver` depends on neither `github.com/pion/webrtc` nor `github.com/pion/turn`.

## 2. Full Automated Verification Suite

Run all unit, TUN, Fyne headless UI, CLI, and acceptance tests under the race detector:

```bash
go test -race -count=1 ./...
```

## 3. Acceptance Test Matrix (`test/acceptance`)

| ID | Test Function | Reproducible Command | Verifiable Invariants |
| --- | --- | --- | --- |
| `ARCH` | `TestArchitectureAndControlPlaneInvariants` | `go test -race -v ./test/acceptance -run TestArchitectureAndControlPlaneInvariants` | Hub excludes `pion/webrtc`, `fyne`, and `sqlite`; stunserver excludes `pion/webrtc` and `pion/turn`; `GET /healthz` returns `{"status":"ok"}`; TLS 1.2 WSS rejected. |
| `T01` | `TestT01_SameLANDirectHostConnectivity` | `go test -race -v ./test/acceptance -run TestT01_SameLANDirectHostConnectivity` | DTLS 1.3/UDP `stuns:` probe succeeds; direct `host`–`host` UDP pair with `DTLSVersion == "FEFC"`; `data/v1` and `packet/v1` deliver payloads; `> 16 KiB` rejected; logs redact SDP, ICE passwords, keys, and payloads. |
| `T02` | `TestT02_PublicIPv4AndIPv6Connectivity` | `go test -race -v ./test/acceptance -run TestT02_PublicIPv4AndIPv6Connectivity` | Separate `IPv4` (`udp4`) and `IPv6` (`udp6`) runs establish direct DTLS 1.3 (`FEFC`) connectivity. |
| `T03` | `TestT03_CompatibleNATsSeparateNetworks` | `go test -race -v ./test/acceptance -run TestT03_CompatibleNATsSeparateNetworks` | Peers behind separate cone NATs traverse via DTLS 1.3/UDP `stuns:` without relay. |
| `T04` | `TestT04_RestrictiveNATsFailClosed` | `go test -race -v ./test/acceptance -run TestT04_RestrictiveNATsFailClosed` | Symmetric NATs with blocked direct UDP and no relay fail closed within timeout. |
| `T05` | `TestT05_PeerSupportsOnlyDTLS12Fails` | `go test -race -v ./test/acceptance -run TestT05_PeerSupportsOnlyDTLS12Fails` | DTLS 1.2-only remote peer fails handshake; zero bytes delivered. |
| `T06` | `TestT06_CompromisedHubTamperingFails` | `go test -race -v ./test/acceptance -run TestT06_CompromisedHubTamperingFails` | Hub mutations to SDP fingerprint, `ice-pwd`, or sender identity fail signature verification before WebRTC installation. |
| `T07` | `TestT07_DeniedBlacklistedAndReplayedSignalingRejected` | `go test -race -v ./test/acceptance -run TestT07_DeniedBlacklistedAndReplayedSignalingRejected` | Nil `Consent` fails closed (`ErrUserDenied`); blacklisted peers fail with `ErrPeerBlacklisted`; replayed v2 signaling rejected at both hub and peer. |
| `T08` | `TestT08_RelayAndHubEndpointCandidatesRejected` | `go test -race -v ./test/acceptance -run TestT08_RelayAndHubEndpointCandidatesRejected` | Plaintext `stun:`/`turn:` fail without `--insecure`; unauthenticated `turns:` fails; relay and hub-endpoint candidates rejected when relay disabled. |
| `T09` | `TestT09_LargeBinaryTransferPacketCapture` | `go test -race -v ./test/acceptance -run TestT09_LargeBinaryTransferPacketCapture` | `512 KiB` SHA-256-verified direct transfer records `0` hub signaling messages and direct peer UDP flow. |
| `T10` | `TestT10_StopHubDuringHealthyDirectSession` | `go test -race -v ./test/acceptance -run TestT10_StopHubDuringHealthyDirectSession` | Active direct session continues uninterrupted when hub stops; fresh negotiations fail closed. |
| `T11` | `TestT11_NetworkChangeAndNATExpiryICERestart` | `go test -race -v ./test/acceptance -run TestT11_NetworkChangeAndNATExpiryICERestart` | Network interface switch completes signed ICE restart (`generation >= 1`); unrecoverable loss fails closed. |
| `T12` | `TestT12_FloodOversizedSignalingAndMalformedSTUN` | `go test -race -v ./test/acceptance -run TestT12_FloodOversizedSignalingAndMalformedSTUN` | `80 KiB` WSS frames, connection bursts, and malformed UDP floods trigger bounds/rate limits while legitimate peers still connect. |
| `T13` | `TestT13_TamperDTLSProtectedRecordNotDelivered` | `go test -race -v ./test/acceptance -run TestT13_TamperDTLSProtectedRecordNotDelivered` | Bit-flipped in-flight DTLS 1.3 ciphertext records are rejected by AEAD without delivering corrupted bytes. |
| `ALGO` | `TestInterKeyAlgorithmSigningTLS13AndDTLS13Matrix` | `go test -race -v ./test/acceptance -run TestInterKeyAlgorithmSigningTLS13AndDTLS13Matrix` | End-to-end interoperability across `ed25519`, `ed448`, `nistp-256`, `nistp-384`, `nistp-521`, and `rsa` identities, TLS 1.3 hub certs, and DTLS 1.3 peer certs. |
| `ICE-SEC` | `TestSTUNSAndTURNSDTLS13UDPAndInsecureOptIn` | `go test -race -v ./test/acceptance -run TestSTUNSAndTURNSDTLS13UDPAndInsecureOptIn` | Plaintext ICE rejected by default; untrusted STUNS CA rejected; DTLS 1.3/UDP TURNS relay connects across loopback and symmetric NATs; opt-in `--insecure` works. |
| `TCP-ONLY` | `TestTCPOnlyModeZeroUDPEndToEnd` | `go test -race -v ./test/acceptance -run TestTCPOnlyModeZeroUDPEndToEnd` | `--tcp-only` binds zero UDP sockets, verifies TLS 1.3/TCP STUNS, rejects UDP candidates, and exchanges `data/v1` and `packet/v1` over ICE-TCP + DTLS 1.3. |
| `CONSENT-TUN` | `TestPassphraseBroadcastIsolationAndUserConsent` | `go test -race -v ./test/acceptance -run TestPassphraseBroadcastIsolationAndUserConsent` | Broadcasts stay strictly isolated to matching offline passphrase; Deny rejects; Allow binds TUN IPv4 routing; Blacklist tears down active tunnel, hides broadcasts, and blocks reconnects. |
| `UNIVERSAL-RELAY` | `TestUniversalPublicRelayAutoProvisionedAcrossSymmetricNATs` | `go test -race -v ./test/acceptance -run TestUniversalPublicRelayAutoProvisionedAcrossSymmetricNATs` | Zero-config hub auto-mints ephemeral DTLS 1.3/UDP TURNS credentials in `registered.relay`, connecting symmetric-NAT peers and routing TUN IPv4 packets with zero manual TURN setup. |
| `HUB-PASSPHRASE` | `TestHubOfflinePassphraseGate` | `go test -race -v ./test/acceptance -run TestHubOfflinePassphraseGate` | Hub configured with offline `--passphrase` rejects missing/wrong passphrases and admits matching peers via challenge-bound HMAC proof. |

## 4. Unit, TUN, and Headless Fyne UI Suites

| Package | Command | Covered Invariants |
| --- | --- | --- |
| `cmd/lighthouse` | `go test -race ./cmd/lighthouse` | Zero-config hub CLI flags, POSIX double-dash enforcement, single-source `pkg/version/version.go` alignment across `lighthouse` and `lighthouse-ui`, runtime `.env`/`LIGHTHOUSE_*` loading |
| `pkg/identity` | `go test -race ./pkg/identity` | Multi-algorithm keygen, `0600` key and blacklist permissions, Argon2id `DeriveChannelKeys`, XChaCha20-Poly1305 `SealBroadcastMeta`/`OpenBroadcastMeta`, hub passphrase HMAC proofs, configurable IPv4 virtual CIDR (`10.88.0.0/16` default) derivation |
| `pkg/protocol` | `go test -race ./pkg/protocol` | v2 wire schemas, `64 KiB` limit, JCS signaling and broadcast signatures, embedded `public_key` binding |
| `pkg/tun` | `go test -race ./pkg/tun` | IPv4/IPv6 header endpoint parsing, bidirectional TUN packet forwarding over DTLS 1.3 WebRTC, outbound and inbound cryptographic source-IP anti-spoofing |
| `internal/ui` | `go test -race ./internal/ui` | Headless Fyne v2 controller binding TUN interface, passphrase-scoped broadcast discovery, explicit Allow/Deny/Blacklist modal workflow, live TUN routing, and blacklist teardown/unblacklist |
| `internal/ui/rawblock` | `go test -race ./internal/ui/rawblock` | RawBlock brutalist Fyne theme tokens (`0px` radii, transparent shadow, embedded fonts) and all components (buttons, cards, inputs, chips, lists, checkboxes, circular radios, tooltips, hyperlinks) |
| `internal/hub` | `go test -race ./internal/hub` | Zero-config AutoTLS startup, hub-side virtual CIDR assignment (`10.88.0.0/16` default and custom CIDRs), automatic passphrase/broadcast ACL enforcement, optional hub passphrase gate, auto-minted universal relay credentials, single-use challenges, session limits, and disconnect broadcast withdrawal |
| `internal/stunserver` | `go test -race ./internal/stunserver` | DTLS 1.3/UDP and TLS 1.3/TCP STUNS Binding, DTLS/TLS 1.2 rejection, TURN `Allocate` rejection, opt-in `AllowInsecure` |
| `internal/turnserver` | `go test -race ./internal/turnserver` | DTLS 1.3/UDP and TLS 1.3/TCP TURNS + STUNS Binding, HMAC TURN REST authentication, `AllowInsecure` gate |
| `internal/jcs` | `go test -race ./internal/jcs` | RFC 8785 UTF-16 sorting, ES6 number canonicalization, duplicate-key rejection |
| `pkg/peer` | `go test -race ./pkg/peer` | `stuns:`/`turns:` defaults, UDP prioritization, `--insecure` and `--tcp-only` guardrails, SDP and candidate filtering |
