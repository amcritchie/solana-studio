# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.4.7 (2026-06-05)

### Added
- **`Solana::Transaction.cosign_wire(signed_wire_bytes, signer:, require_complete:)`** — client-first cosign. Adds one signature to an already-(partially-)signed wire tx WITHOUT rebuilding it: parses the compact-u16 signature count + message header, finds the signer's account-key index, asserts that slot is currently zero (never clobbers a real signature), signs the EXACT message bytes, writes the 64-byte signature in, and (when `require_complete:`, default true) re-asserts OPSEC-017 — every required slot non-zero. Pure Ruby, no RPC. Enables the Phantom-signs-FIRST / server-cosigns-SECOND entry flow that clears Phantom's multi-signer-order "could be malicious" Lighthouse banner. `cosign_wire_base64` is the base64 wrapper.
- **`Solana::Transaction.read_compact_u16(bytes, offset)`** — ShortVec compact-u16 decoder, `[value, next_offset]` (wire-parser primitive behind `cosign_wire`).

### Tests
- `test/transaction_test.rb` (+9 tests): correct slot filled + verifies over message, other signer's sig + message bytes untouched, 2/2 sigs valid, refuses to clobber a filled slot, rejects a non-signer, off-by-one slot guard, malformed-header count-mismatch rejection, base64 round-trip.

## v0.4.6 (2026-06-02)

### Added
- **`Solana::SystemProgram`** — System-Program instruction encoders for durable nonce support: `create_account` (ix 0), `advance_nonce_account` (4), `withdraw_nonce_account` (5), `initialize_nonce_account` (6), `authorize_nonce_account` (7). Plus constants `RECENT_BLOCKHASHES_SYSVAR`, `RENT_SYSVAR`, `NONCE_ACCOUNT_LENGTH` (80). A durable nonce lets a tx stay valid indefinitely (until consumed) instead of expiring with a ~90s recent blockhash — the canonical pattern for long / async / multi-party signing.
- **`Solana::NonceAccount.parse(bytes)`** — parses an 80-byte nonce account (version, state, authority, stored nonce, lamports_per_signature) with `initialized?` + `authority?(expected)` guards.

### Tests
- `test/system_program_test.rb` (8 tests): **byte-match** each encoder against the exact `@solana/web3.js` layout (u32 LE index + fields, account metas + signer flags), nonce-account parse round-trip (init + uninit), and an advance-instruction-into-partial-tx composition check.

## v0.4.5 (2026-06-02)

### Fixed
- **Fully keyless `serialize_partial`** — a build with zero local `@signers` (every required signature supplied externally) now works: the empty-signers guard fires only when neither a local nor an additional signer is present, the fee payer falls back to the first additional signer, and `@signers.drop(1)` is nil-safe. Enables the no-server-key multi-party signing console. (v0.4.4 began this; v0.4.5 completed the fee-payer/signers fallback.)

## v0.4.3 (2026-05-27)

### Fixed
- **`Solana::Client#http_post` now preserves the query string when constructing the `Net::HTTP::Post` path** (was: dropped). RPC providers that carry their API key on the query — Helius (`https://devnet.helius-rpc.com/?api-key=…`), QuickNode, Triton — previously received an authless request and replied with their equivalent of `"missing api key"`, breaking every RPC call. `@uri.request_uri` is the correct accessor (path + "?" + query); `@uri.path` returns only the path portion. Surfaced when turf-monster moved off the public devnet endpoint to Helius.

### Tests
- New `test/client_test.rb` (2 tests): asserts `http_post` builds the request with the full request-URI (path + query) when the RPC URL carries a query string, and falls back to `"/"` when path is empty.

## v0.4.2 (2026-05-19)

Tier-3 fixes from the turf-monster pre-prod opsec audit (OPSEC-017/018/043).

### Changed (breaking)
- **`Solana::AuthVerifier.verify!` now requires an `expected_host:` keyword argument (OPSEC-018).** The verifier previously matched only the nonce, so a signature a user produced for any other dApp — over a message carrying the same nonce — would satisfy a host app's login. `verify!` now asserts the signed message names `expected_host` as its opening token (SIWS-style `"<host> wants to sign in…"`). Callers must pass `expected_host:` (e.g. `request.host`).

### Fixed (security)
- **`Solana::Transaction#serialize` / `#serialize_partial` now verify signer count (OPSEC-017).** `serialize` raises unless `@signers.length` equals the number of `is_signer` accounts; `serialize_partial` raises unless local + additional signers cover every required slot. Previously a missing required signer produced a malformed payload, or a zero-filled signature slot in a still-broadcastable half-signed TX.
- **`Solana::Transaction#serialize_partial` no longer stores signer state in an instance variable (OPSEC-043).** Additional signers are kept in a local, so a `Transaction` shared across threads can't leak signer state between partial-sign flows.

### Tests
- New `test/auth_verifier_test.rb`; added signer-count + no-instance-state cases to `test/transaction_test.rb`.

## v0.4.1 (2026-05-17)

Pre-public-release security hardening per `SECURITY-AUDIT-2026-05-17.md`.

### Fixed (security)
- **TLS enforcement in `Solana::Client`** — explicit `OpenSSL::SSL::VERIFY_PEER` and `TLS1_2_VERSION` minimum on every HTTPS RPC connection. Belt-and-suspenders against future downstream Net::HTTP regressions.
- **HTTPS-only RPC URL validation** — `Solana::Client` constructor now raises `Solana::Client::InsecureRpcUrlError` on `http://` URLs unless the host is `localhost`/`127.0.0.1`/`::1`. Prevents cleartext RPC traffic to public providers.
- **Borsh allocation-bomb guard** — `Solana::Borsh::MAX_DECODED_FIELD_BYTES = 10MB`. New `decode_string` + `decode_vec` helpers check the length prefix before allocating; raise `Solana::Borsh::DecodedFieldTooLarge` on overage. Protects callers from corrupt or malicious RPC responses.
- **Constant-time nonce compare in `Solana::AuthVerifier`** — `OpenSSL.fixed_length_secure_compare` replaces Ruby string `==`. Removes a (low-practical-impact) timing side channel.
- **Pubkey + signature length validation in `Solana::AuthVerifier.verify!`** — explicit checks before `Ed25519::VerifyKey.new` so malformed inputs raise `VerificationError("Public key must be 32 bytes...")` instead of being masked by the generic `"Signature verification failed"` catch-all.
- **Base58 input validation in `Solana::Keypair.decode_base58`** — explicit alphabet check raises `ArgumentError` with a clear message on invalid chars (`0`, `O`, `I`, `l`) instead of producing a confusing `TypeError` deep in the multiplication loop.

### Changed
- `Solana::AuthVerifier` docstring now loudly states caller's responsibility for nonce invalidation (delete-before-verify pattern) and links to the canonical Rails session-adapter at `turf-monster/app/controllers/concerns/solana/session_auth.rb`.
- Gemspec author email changed from `alex@mcritchie.studio` (personal) to `solana-studio@mcritchie.studio` (project alias).

## v0.4.0 (2026-05-17)

### Changed (breaking)
- **Gem renamed from `solana_studio` to `solana-studio`.** Repo URL is now `github.com/amcritchie/solana-studio` (was `.../solana_studio`). Consumers must update their `Gemfile`:
  ```ruby
  # Before:
  gem "solana_studio", git: "https://github.com/amcritchie/solana_studio.git", tag: "v0.3.0"
  # After:
  gem "solana-studio", git: "https://github.com/amcritchie/solana-studio.git", tag: "v0.4.0"
  ```
- The Ruby `SolanaStudio` module name and the `Solana::*` namespace are **unchanged** — all call sites keep working without code changes.
- Gem entry point at `lib/solana-studio.rb` (a thin `require_relative "solana_studio"` shim) ensures `gem "solana-studio"` auto-requires correctly without a `require:` option in the Gemfile.

### Added
- gemspec `metadata` (homepage / source / bugs / changelog URIs) — getting ready for RubyGems publishing.

## v0.3.0 (2026-05-17)

### Added
- **`Solana::AuthVerifier`** — pure module for verifying Phantom wallet signatures against an externally-stored nonce. Extracted from turf-monster's `app/services/solana/auth_verifier.rb`. Host apps keep a thin session adapter that delegates to `Solana::AuthVerifier.verify!`.
- `Solana::AuthVerifier::VerificationError`, `Solana::AuthVerifier::NONCE_MAX_AGE` constants now live in the gem.
- Updated CLAUDE.md with the gem-vs-app split rule for Solana code.

### Fixed
- gemspec `spec.version` was bumped to "0.3.0" after the initial release (had been mistakenly left at "0.2.0").

## v0.2.0 (2026-04-03)

- SPL Token instruction builders (`create_associated_token_account`, `mint_to`, `transfer`)
- Test suite: Keypair, Borsh, and Transaction tests (9 tests)
- Updated CLAUDE.md with test documentation

## v0.1.0 (2026-04-02)

- Initial release
- `Solana::Client` — JSON-RPC over HTTP with retry logic
- `Solana::Keypair` — Ed25519 keygen, base58, sign, `from_base58` for env var loading
- `Solana::Borsh` — encode/decode primitives (u8, u16, u32, u64, i64, pubkey, string, vec, bool)
- `Solana::Transaction` — transaction builder, PDA derivation, Anchor discriminators, on_curve? check
