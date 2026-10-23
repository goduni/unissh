# unissh-cloud

The client side of a self-hosted UniSSH server's `/v1` API. The core
(`unissh-ffi`) is deliberately network-less: it builds, signs and verifies every
blob, and runs the sync engine against a transport it does not trust. This crate
is that transport and the rest of the wire, shared by the desktop app
(`client/src-tauri`) and the headless CLI so the two speak exactly one protocol.

## Modules

- `client` — the process-global blocking HTTP client (rustls), base64 STANDARD
  helpers, the server's error envelope, `429` back-off and one `401` retry after
  a token rotation the embedding app supplies (`set_reauth`). Plaintext `http://`
  is refused for anything but loopback (`validate_base_url`).
- `identity` — claim, invite join, the challenge-signed login, session refresh and
  logout, devices (add, list, revoke, keyset-signed self-enroll), spaces,
  directory, pending actions, attestations, keyset escrow and the pairing relay.
- `transport` — `HttpSyncTransport`, the `FfiSyncTransport` the core's sync engine
  drives: push with a content-stable `Idempotency-Key`, paged delta pulls, and the
  per-vault catalog/delta used to pull one vault.
- `onboard` — device-to-device pairing (Path B): the PAKE messages over the
  untrusted relay, initiator and responder sides.
- `recovery` — installing a keyset recovered from escrow or an Emergency Kit.
- `dto` — the server's answers shaped for a client (`camelCase`; the desktop app
  hands them to its UI verbatim).

## What the embedding application provides

- **Platform hooks** (`client::install_platform`): the `User-Agent`, a builder hook
  and a per-call preparation hook. The desktop app uses them for Android's
  certificate verifier (#34); the CLI needs none.
- **Where a Secret Key is remembered.** Pairing and recovery hand the account's
  Secret Key to a callback — the app's OS keychain, the CLI's own store — and
  never keep it themselves.
- **Token rotation** (`client::set_reauth`), for an app that holds refresh tokens.

## Security

The server is untrusted for confidentiality and integrity: every object it relays
was encrypted and signed by a core and is verified by the receiving core before it
is applied. Bearer tokens and request bodies are never logged; transport errors
log the error chain only. Escrow parameters from the server are clamped by the
core before any key derivation.

## Tests

Unit tests cover the base64/URL helpers, TLS error hints, the `401` rotation
retry against a scripted local server, delta paging and recovery installation.
`tests/live_e2e.rs` drives the whole chain — claim, invite join, sync between
accounts, pairing and escrow recovery — against a real `unissh-server`; it is
ignored by default:

```bash
cargo build -p unissh-server
cargo test -p unissh-cloud --test live_e2e -- --ignored --nocapture
```
