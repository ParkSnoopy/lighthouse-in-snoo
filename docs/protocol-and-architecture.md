# Protocol, Wire Formats, and Architecture

## 1. System Architecture

Lighthouse separates the network into two components:

1. **Blinded Zero-Config Universal Hub (`cmd/lighthouse` / `internal/hub`)**: A `CGO_ENABLED=0` static `linux/amd64` server (packaged on `debian:13-slim`) with no hub passphrase, static ACL policy files, or database. It provides:
   - TLS 1.3 WSS signaling (`/v1/signal`) and privacy-preserving health endpoints (`/` and `/healthz`), auto-generating and persisting `tls.crt`/`tls.key` in `/etc/lighthouse` on initial container startup using `--tls-algo` (`LIGHTHOUSE_TLS_ALGO`, default `ed25519`; supports `ed25519`, `nistp-256`, `nistp-384`, `nistp-521`, `rsa`) with in-memory fallback when non-writable. The listener honors `PORT` when `LIGHTHOUSE_HTTPS_ADDR` is unset, multiplexes plaintext HTTP/WebSocket traffic forwarded by TLS-terminating reverse proxies (Cloudtype, Nginx, Caddy, Kubernetes Ingress) from private, loopback, link-local, or CGNAT addresses while rejecting TLS 1.2 and public plaintext HTTP, and responds to client `heartbeat` frames with RFC 6455 WebSocket `Ping` control frames so reverse-proxy idle read timeouts (e.g. Cloudtype Free Tier `60 s`) never drop live peers.
   - Optional single-domain runtime auto-configuration (`--domain` / `LIGHTHOUSE_DOMAIN` in `.env` or process environment): pins canonical `wss://<domain>` hub origin, TURN advertise host and realm, and auto-generated TLS certificate SAN; when omitted, the hub dynamically accepts any incoming domain or forwarded port (including PaaS rotating domains such as Cloudtype) while keeping per-connection challenge-origin binding intact. Clients accept bare domains (`hub.example.com` or `host:port`) without `wss://` or `/v1/signal` boilerplate.
   - Hub-managed IPv4 CIDR assignment (`--cidr` / `LIGHTHOUSE_CIDR`, default `10.88.0.0/16`), advertising `virtual_cidr` and `assigned_ip` in `registered`.
   - Passphrase-bucketed room forwarding (opaque 32-byte `channel_id` tokens; the hub accepts any peer and never sees raw passphrases or decrypted peer labels).
   - Automatic room-scoped server-side ACL derived purely from live passphrase room membership and active broadcast status: a peer may initiate a new signaling session to target `B` if and only if `B` is actively broadcasting in a room (`channel_id`) that the caller has joined or is also broadcasting in.
   - Time-based peer presence expiry (`PresenceTTL`, default `60 s`): expired peers are automatically forgotten and empty rooms with zero active peers are pruned from memory.
   - Integrated universal DTLS 1.3 / UDP STUNS + TURNS relay (`:5349/udp`) that automatically mints 12-hour HMAC TURN REST credentials in `registered.relay` for every registered peer (or TLS 1.3 / TCP STUNS with zero UDP sockets under `--tcp-only`).
2. **Bound OS Virtual Interface App (`cmd/lighthouse-ui` / `internal/ui` / `pkg/tun` / `pkg/peer`)**: A Fyne desktop application that registers with the hub to receive its hub-assigned IP/CIDR and binds a local OS TUN virtual interface (`lh0`) directly to user-authorized DTLS 1.3 WebRTC tunnels.

## 2. Protocol Stack

```text
OS IPv4 / IPv6 packets via TUN virtual interface (lh0, default 10.88.0.0/16, MTU 1380)
TUN Router (pkg/tun): strict cryptographic source-IP anti-spoofing
WebRTC DataChannel / DCEP ("packet/v1" unordered datagrams, "data/v1" ordered fallback, <= 16 KiB)
SCTP (congestion control active, max-message-size = 16384)
DTLS 1.3 (RFC 9147, 0xFEFC, ECDHE + AEAD, replay window = 64, 0-RTT disabled)
ICE-selected UDP transport (host / srflx / prflx / universal DTLS 1.3 TURNS relay; or ICE-TCP with --tcp-only)
IPv4 / IPv6
```

Transport prioritization:

- `stuns:<host>[:<port>]` (default `5349`): STUN Binding over DTLS 1.3 / UDP on the shared ICE UDP socket.
- `turns:<host>[:<port>]` (default `5349`): Universal relay over DTLS 1.3 / UDP (`?transport=udp`) by default; `?transport=tcp` uses TLS 1.3 / TCP when explicitly requested.
- `--tcp-only` (`TCPOnly: true` / `LIGHTHOUSE_TCP_ONLY=true`): Binds zero UDP sockets on hub and peers, serves STUNS over TLS 1.3 / TCP (RFC 8489 framing on `:5349/tcp`), rejects `?transport=udp` and UDP candidates, and runs DTLS 1.3 DataChannels over RFC 6544 / RFC 4571 ICE-TCP.
- Plaintext `stun:` and `turn:` (default `3478`) are rejected by default and require explicit `--insecure` (`AllowInsecure` / `AllowInsecureICE`).

## 3. Cryptographic Identity, Passphrase Scoping, and Consent Core

### 3.1 Peer Identities and Deterministic Virtual IP

- Supported signing algorithms (`--algo`):
  - `ed25519` (default, RFC 8032): unpadded `base64url` raw 32-byte key; `peer_id = base64url(SHA-256(raw_32_bytes))`.
  - `ed448` (RFC 8032): `ed448:<base64url(raw_57_bytes)>`; `peer_id = base64url(SHA-256("ed448\x00" || raw_57_bytes))`.
  - `nistp-256`, `nistp-384`, `nistp-521`: `<algo>:<base64url(PKIX_SPKI_DER)>`; `peer_id = base64url(SHA-256("<algo>\x00" || spki_der))`.
  - `rsa` (RSA-PSS + SHA-256, `2048`–`8192` bits, default `3072`): `rsa:<base64url(PKIX_SPKI_DER)>`; `peer_id = base64url(SHA-256("rsa\x00" || spki_der))`.
- Private keys and local blacklist files (`blacklist.json`) are saved atomically with `0600` permissions and rejected if group/world-accessible.
- Every `peer_id` deterministically maps to a usable host TUN IPv4 address via `SHA-256("LIGHTHOUSE-TUN-IPV4-V2\x00" || peer_id)` inside the hub's configured IPv4 CIDR (`lighthouse hub --cidr` / `LIGHTHOUSE_CIDR`, default `10.88.0.0/16`, `/1`–`/30`, excluding network and broadcast addresses). Peers validate the hub-advertised `virtual_cidr` and `assigned_ip` during `registered` before binding TUN.

### 3.2 Offline Passphrase Room Derivation

Raw passphrases never leave the peer process and are never configured on the hub:

- **Blinded Rooms (`identity.DeriveChannelKeys`)**: Argon2id (`time=1, memory=16 MiB, threads=2`, salt `"LIGHTHOUSE-CHANNEL-V2"`) derives 64 bytes:
  - Bytes `[0:32]` → 43-char base64url `channel_id` sent to the hub to dynamically form an isolated room.
  - Bytes `[32:64]` → 32-byte XChaCha20-Poly1305 AEAD key (`AuthKey`) used to seal/open `BroadcastMeta` (`display_name`) with AAD `peer_id || "\x00" || channel_id`.

### 3.3 Explicit User Consent & Local Blacklist

Security authorization lives exclusively at the user's client (`peer.ConsentHandler`):

- Incoming offers are cryptographically verified (embedded `public_key` bound to `from` `peer_id`, JCS signature, TTL, replay history, SDP candidate policy) **before** prompting the user.
- If `Consent == nil`, the client fails closed to `ConsentDeny`.
- Incoming ICE candidates arriving while awaiting the user's modal prompt are buffered in `preConsentQueue` without blocking the signaling loop.
- Decisions:
  - `ConsentAllow`: applies remote SDP, sends signed Answer, completes DTLS 1.3 handshake, and binds the verified session into `tun.Router`.
  - `ConsentDeny`: transmits signed `close` (`reason: "user_denied"`) and discards the offer.
  - `ConsentBlacklist`: persists the peer to `blacklist.json` (`0600`), closes any active tunnel (`reason: "blacklisted"`), hides its broadcasts, and auto-rejects all future offers without prompting.

### 3.4 Domain-Separated Signatures (v2)

All signed frames use RFC 8785 JCS (`internal/jcs`), rejecting invalid UTF-8, duplicate object keys, trailing tokens, and unknown fields.

| Purpose | Domain Prefix | Signed Payload |
| --- | --- | --- |
| Hub Registration | `"LIGHTHOUSE-REGISTER-V1\x00"` | `JCS({"challenge", "hub_origin", "peer_id"})` |
| Passphrase Broadcast | `"LIGHTHOUSE-BROADCAST-V2\x00"` | `JCS(BroadcastMessage excluding "sig")` |
| P2P Signaling Envelope | `"LIGHTHOUSE-SIGNAL-V2\x00"` | `JCS(SignalEnvelope excluding "sig")` |

## 4. Control-Plane Wire Protocol (v2)

- `GET /` and `GET /healthz`: HTTP `200` `{"status":"ok"}`, `Cache-Control: no-store`.
- `WSS /v1/signal`: TLS 1.3 exclusively (or plaintext HTTP/WS behind trusted TLS-terminating reverse proxies), UTF-8 JSON text frames, `64 KiB` frame cap, single-use 32-byte challenges (`60 s` expiry), `20 s` heartbeats (answered with RFC 6455 WebSocket `Ping` keepalives) / `60 s` leases.

| Type | Direction | Description |
| --- | --- | --- |
| `challenge` | Hub → Peer | Single-use challenge and canonical `hub_origin` |
| `register` | Peer → Hub | `v:2`, `peer_id`, `public_key`, `hub_origin`, `challenge`, `proof` |
| `registered` | Hub → Peer | Confirmation, lease TTL, heartbeat interval, hub `virtual_cidr` / `assigned_ip`, and auto-minted universal `relay` credentials |
| `heartbeat` | Peer → Hub | Presence lease renewal |
| `channel_join` | Peer → Hub | Subscribe to broadcasts for opaque `channel_id` |
| `channel_leave` | Peer → Hub | Unsubscribe and withdraw any active broadcast on `channel_id` |
| `broadcast` | Peer → Hub | Signed self-announcement (`active: true/false`, `sealed_meta`) scoped to `channel_id` |
| `channel_peers` | Hub → Peer | Current snapshot of active signed broadcasts on `channel_id` |
| `offer` / `answer` | Peer → Peer | Signed v2 envelope embedding sender `public_key` and unmodified SDP |
| `candidate` / `end_of_candidates` | Peer → Peer | Signed v2 trickled ICE candidate / gathering terminator |
| `close` | Peer → Peer | Signed v2 cancellation or closure (`user_denied`, `blacklisted`, `normal_close`) |
| `error` | Hub → Peer | Machine-readable failure code (`code`, optional `detail`, optional `session_id`) |

FIFO ordering invariant: the hub delivers `close` frames to recipients before marking a negotiation record closed, and the peer client processes `error` and signaling envelopes in strict single-queue FIFO order so user-initiated close reasons (`user_denied`, `blacklisted`) are never preempted by post-close in-flight candidate rejections.

## 5. TUN Forwarding & Anti-Spoofing (`pkg/tun`)

`tun.Router` binds a `tun.Device` (Linux `/dev/net/tun` `IFF_TUN | IFF_NO_PI` or in-memory `MemoryDevice` for tests) to active peer sessions:

- **Outbound**: reads raw IP packets from TUN, verifies `src == localVirtualIP`, looks up the authorized `*peer.Session` by destination virtual IP, and transmits over `packet/v1` (falling back to `data/v1`). Unrouted or spoofed-source packets are dropped and counted.
- **Inbound**: verifies `src == session.RemoteVirtualIP() && dst == localVirtualIP` on every packet arriving from a remote peer before writing to TUN. Any spoofed packet is dropped and counted (`DroppedSpoofed`).

## 6. Reference Dependencies

| Module | Role |
| --- | --- |
| `github.com/pion/webrtc/v5` | Native Go WebRTC PeerConnection, ICE, SCTP, DCEP |
| `github.com/pion/dtls/v4` | DTLS 1.3 (RFC 9147) for peer transport and RFC 7350 DTLS/UDP STUNS/TURNS |
| `github.com/pion/ice/v5` | Full ICE agent and candidate parser |
| `github.com/pion/stun/v5` | RFC 8489 STUN wire codec |
| `github.com/pion/turn/v6` | RFC 8656 universal DTLS/UDP TURNS relay |
| `github.com/pion/sdp/v3` | SDP parsing and pre-installation policy inspection |
| `github.com/pion/transport/v5` | Network abstraction and `vnet` virtual NAT/router testing |
| `github.com/coder/websocket` | Bounded TLS 1.3 WebSocket client and server |
| `github.com/cloudflare/circl` | RFC 8032 Ed448 identity signatures |
| `golang.org/x/crypto` | Argon2id passphrase KDF and XChaCha20-Poly1305 AEAD |
| `fyne.io/fyne/v2` | Cross-platform desktop UI (`cmd/lighthouse-ui`, `internal/ui`) |
| `github.com/go-critic/go-critic` | Go `tool` linter (standard profile overall; `-enableAll` on security packages) |
