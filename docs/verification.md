# Verification Procedures and Invariants

## 1. Build and Static Analysis Commands

Verify static `linux/amd64` compilation (`CGO_ENABLED=0`), hub dependency isolation, and `go vet` from a fresh clone:

```bash
CGO_ENABLED=0 GOARCH=amd64 go build ./...
go vet ./...
go list -deps ./internal/hub | grep 'github\.com/pion/webrtc' && exit 1 || true
go list -deps ./internal/stunserver | grep -E 'github\.com/pion/(webrtc|turn)' && exit 1 || true
```

### Verifiable Build Invariants

- `cmd/lighthouse` compiles into a single static `linux/amd64` Go binary (`CGO_ENABLED=0`) containing the `hub`, `peer`, and `admin` subcommands.
- `go list -deps ./internal/hub` never includes `github.com/pion/webrtc`, proving the hub cannot instantiate a WebRTC `PeerConnection` or terminate peer DTLS 1.3 sessions.
- `go list -deps ./internal/stunserver` includes neither `github.com/pion/webrtc` nor `github.com/pion/turn`.

## 2. Full Automated Verification Suite

Run all unit and acceptance tests with the Go race detector enabled:

```bash
go test -race -v ./...
```

## 3. Acceptance Criteria Mapping (`T01`–`T13`, Inter-Algorithm, STUNS/TURNS)

Each acceptance requirement in `test/acceptance` exercises independently authenticated `pkg/peer.Client` instances coordinated by an `internal/hub.Server` instance.

| ID | Test Function | Reproducible Command | Verifiable Invariants |
| --- | --- | --- | --- |
| `ARCH` | `TestArchitectureAndControlPlaneInvariants` | `go test -race -v ./test/acceptance -run TestArchitectureAndControlPlaneInvariants` | `internal/hub` excludes `pion/webrtc`; `internal/stunserver` excludes `pion/webrtc` and `pion/turn`; `GET /healthz` exposes only `{"status":"ok"}`; TLS 1.2 WSS clients fail handshake. |
| `T01` | `TestT01_SameLANDirectHostConnectivity` | `go test -race -v ./test/acceptance -run TestT01_SameLANDirectHostConnectivity` | DTLS 1.3 / UDP `stuns:` probe succeeds; direct `host`–`host` UDP pair selected; `DTLSVersion == "FEFC"` (DTLS 1.3); `data/v1` and `packet/v1` deliver payloads; `> 16 KiB` messages return `ErrMessageTooLarge`; logs omit SDP, ICE passwords, keys, candidates, and payloads. |
| `T02` | `TestT02_PublicIPv4AndIPv6Connectivity` | `go test -race -v ./test/acceptance -run TestT02_PublicIPv4AndIPv6Connectivity` | Separate `IPv4` (`udp4`) and `IPv6` (`udp6`) runs establish direct connectivity over DTLS 1.3 (`FEFC`) with DTLS 1.3 `stuns:`. |
| `T03` | `TestT03_CompatibleNATsSeparateNetworks` | `go test -race -v ./test/acceptance -run TestT03_CompatibleNATsSeparateNetworks` | Peers behind separate `192.168.10.0/24` and `192.168.20.0/24` cone NATs discover `srflx` mappings over DTLS 1.3 / UDP `stuns:203.0.113.10:5349` and establish a non-relayed `srflx`/`prflx` pair over DTLS 1.3. |
| `T04` | `TestT04_RestrictiveNATsFailClosed` | `go test -race -v ./test/acceptance -run TestT04_RestrictiveNATsFailClosed` | Peers behind symmetric NATs with blocked direct UDP and no TURNS relay fail closed (`ErrConnectTimeout`, `StateFailed`) within the configured deadline. |
| `T05` | `TestT05_PeerSupportsOnlyDTLS12Fails` | `go test -race -v ./test/acceptance -run TestT05_PeerSupportsOnlyDTLS12Fails` | Connection between a conformant DTLS 1.3 peer and a DTLS 1.2-only peer fails handshake; zero application bytes are delivered. |
| `T06` | `TestT06_CompromisedHubTamperingFails` | `go test -race -v ./test/acceptance -run TestT06_CompromisedHubTamperingFails` | Hub mutations to SDP `sha-256` fingerprint, `ice-pwd`, or `from` sender identity fail signature verification at the recipient prior to WebRTC installation. |
| `T07` | `TestT07_UnknownForbiddenAndReplayedSignalingRejected` | `go test -race -v ./test/acceptance -run TestT07_UnknownForbiddenAndReplayedSignalingRejected` | Unrecognized peers fail registration; unauthorized peer pairs fail lookup/signaling (`unauthorized_pair`); replayed signed envelopes are rejected at both hub (`replayed_signaling`) and peer (`ErrReplayedSignaling`). |
| `T08` | `TestT08_RelayAndHubEndpointCandidatesRejected` | `go test -race -v ./test/acceptance -run TestT08_RelayAndHubEndpointCandidatesRejected` | Plaintext `stun:`/`turn:` fail without `--insecure` (`ErrInsecureICEProhibited`); `turns:` without credentials fails; `typ relay` candidates in SDP or Trickle ICE fail when TURN is not configured; hub endpoint candidates fail validation. |
| `T09` | `TestT09_LargeBinaryTransferPacketCapture` | `go test -race -v ./test/acceptance -run TestT09_LargeBinaryTransferPacketCapture` | A `512 KiB` (`32 x 16 KiB`) SHA-256-verified transfer records `>= 512 KiB` of direct peer-to-peer UDP bytes, `0` signaling messages forwarded during transfer, and zero application bytes traversing the hub STUNS port. |
| `T10` | `TestT10_StopHubDuringHealthyDirectSession` | `go test -race -v ./test/acceptance -run TestT10_StopHubDuringHealthyDirectSession` | Stopping the hub leaves an established `Connected` direct session transferring `64 KiB` of data uninterrupted while new `Connect` attempts fail closed. |
| `T11` | `TestT11_NetworkChangeAndNATExpiryICERestart` | `go test -race -v ./test/acceptance -run TestT11_NetworkChangeAndNATExpiryICERestart` | Switching a peer's network interface suspends unverified traffic, performs a signed ICE restart (`generation >= 1`), and resumes direct transfer on the new IP; unrecoverable path loss exhausts `MaxICERestarts` and transitions to `StateFailed`. |
| `T12` | `TestT12_FloodOversizedSignalingAndMalformedSTUN` | `go test -race -v ./test/acceptance -run TestT12_FloodOversizedSignalingAndMalformedSTUN` | `80 KiB` WSS frames close with `StatusMessageTooBig`; connection bursts trigger HTTP `429` rate limits; malformed, oversized, and plaintext TURN `Allocate` UDP floods to the DTLS 1.3 STUNS port increment rejection counters while legitimate peers connect. |
| `T13` | `TestT13_TamperDTLSProtectedRecordNotDelivered` | `go test -race -v ./test/acceptance -run TestT13_TamperDTLSProtectedRecordNotDelivered` | In-flight bit flips on DTLS 1.3 ciphertext records (`IsDTLS13Ciphertext`) are dropped by AEAD verification and never delivered to `Session.Packets()`, while subsequent untampered records arrive intact. |
| `ALGO` | `TestInterKeyAlgorithmSigningTLS13AndDTLS13Matrix` | `go test -race -v ./test/acceptance -run TestInterKeyAlgorithmSigningTLS13AndDTLS13Matrix` | Interoperability across `ed25519`, `ed448`, `nistp-256`, `nistp-384`, `nistp-521`, and `rsa` identities, cross-algorithm CA/leaf TLS 1.3 WSS + DTLS 1.3 / UDP STUNS certificates, and cross-algorithm peer DTLS 1.3 certificates. |
| `ICE-SEC` | `TestSTUNSAndTURNSDTLS13UDPAndInsecureOptIn` | `go test -race -v ./test/acceptance -run TestSTUNSAndTURNSDTLS13UDPAndInsecureOptIn` | Plaintext `stun:`/`turn:` rejected by default; untrusted STUNS CA rejected; DTLS 1.3 / UDP `turns:` relay establishes end-to-end DTLS 1.3 (`FEFC`) sessions on loopback and across symmetric NATs; opt-in `--insecure` enables plaintext `stun:`/`turn:`. |

## 4. Unit Test Suites

| Package | Command | Covered Invariants |
| --- | --- | --- |
| `cmd/lighthouse` | `go test -race ./cmd/lighthouse` | Clap/POSIX flag rules, `VERSION`/`README.md` sync, runtime-only `LIGHTHOUSE_*` env/`.env` loading, `--insecure` rejection on hub and peer CLI |
| `internal/jcs` | `go test -race ./internal/jcs` | RFC 8785 UTF-16 key sorting, ES6 number canonicalization, duplicate-key rejection, strict field decoding |
| `pkg/identity` | `go test -race ./pkg/identity` | Multi-algorithm keygen, `0600` file mode enforcement, `peer_id` derivation, registration proofs, authority memberships, ACLs, revocations |
| `pkg/protocol` | `go test -race ./pkg/protocol` | 12 message schemas, `64 KiB` limit, JCS envelope signatures, clock skew and TTL bounds |
| `internal/stunserver` | `go test -race ./internal/stunserver` | DTLS 1.3 / UDP IPv4/IPv6 `XOR-MAPPED-ADDRESS`, DTLS 1.2 rejection, TURN `Allocate` error rejection, opt-in `AllowInsecure` plaintext UDP |
| `internal/turnserver` | `go test -race ./internal/turnserver` | DTLS 1.3 / UDP TURNS + STUNS Binding, HMAC TURN REST authentication, `AllowInsecure` gate for plaintext UDP TURN |
| `internal/store` | `go test -race ./internal/store` | Pure-Go SQLite persistence of authorities, peers, memberships, ACL rules, and revocations |
| `internal/hub` | `go test -race ./internal/hub` | Unauthenticated gating, single-use challenges, concurrent-session caps, live revocation eviction |
| `pkg/peer` | `go test -race ./pkg/peer` | `stuns:`/`turns:` default enforcement, UDP prioritization, `--insecure` opt-in, audio/video and `ice-lite` SDP rejection, candidate filtering |
