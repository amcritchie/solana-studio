# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
