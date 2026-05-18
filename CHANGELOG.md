# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.4.0 (2026-05-17)

### Changed (breaking)
- **Gem renamed from `solana_studio` to `solana-studio`.** Repo URL is now `github.com/amcritchie/solana-studio`. Consumers must update their `Gemfile`:
  ```diff
  - gem "solana_studio", git: "https://github.com/amcritchie/solana_studio.git", tag: "v0.3.0"
  + gem "solana-studio", git: "https://github.com/amcritchie/solana-studio.git", tag: "v0.4.0"
  ```
- The Ruby `SolanaStudio` module name and the `Solana::*` namespace are **unchanged** — all call sites keep working without code changes.
- Gem entry point at `lib/solana-studio.rb` (a thin `require_relative "solana_studio"` shim) ensures `gem "solana-studio"` auto-requires correctly without a `require:` option in the Gemfile.

### Added
- gemspec `metadata` (homepage / source / bugs / changelog URIs) — getting ready for RubyGems publishing.

## v0.3.0 (2026-05-17)

### Added
- **`Solana::AuthVerifier`** — pure module for verifying Phantom wallet signatures against an externally-stored nonce. Extracted from turf_monster's `app/services/solana/auth_verifier.rb`. Host apps keep a thin session adapter that delegates to `Solana::AuthVerifier.verify!`.
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
