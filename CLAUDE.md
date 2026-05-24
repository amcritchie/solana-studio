# SolanaStudio Gem

Generic Solana primitives for Ruby. Extracted from Turf Monster's `app/services/solana/` layer.

## Architecture

- `Solana::Keypair` — Ed25519 key management, base58 encode/decode
- `Solana::Client` — JSON-RPC HTTP client with retry (rate limit + blockhash expiry)
- `Solana::Borsh` — Borsh binary serialization (little-endian)
- `Solana::Transaction` — Transaction builder, PDA derivation, Anchor discriminators
- `Solana::SplToken` — SPL Token instruction builders (associated account, mint, transfer)
- `Solana::AuthVerifier` — verify wallet signatures against an externally-stored nonce (pure, host adapts session storage)

## Gem-vs-App Split Rule

> If it talks to an arbitrary Anchor program: gem. If it talks to a specific program's business logic: app.

The gem owns **primitives** — things any Solana-touching Ruby app would need (RPC, signing, serialization, PDA derivation, signature verification). The host app owns **program-specific logic** — config (program IDs, mints), business-layer wrappers like `Solana::Vault`, balance reconciliation against a specific schema.

For shared concerns that need host-specific glue (e.g. Rails session for `AuthVerifier`), the gem provides a pure class method, the host keeps a tiny adapter module that calls it. See `turf-monster/app/services/solana/auth_verifier.rb` for the canonical adapter shape.

## API Reference

### Solana::Keypair
- `Keypair.generate` — new random Ed25519 keypair
- `Keypair.from_base58(secret_key_base58)` — load from env var
- `Keypair.from_bytes(byte_array)` — load from raw bytes
- `Keypair.from_json_file(path)` — load from Solana CLI JSON file
- `keypair.public_key` — 32-byte public key
- `keypair.address` — base58 public key string
- `keypair.sign(message)` — Ed25519 signature (64 bytes)

### Solana::Client
- `Client.new(rpc_url)` — connect to RPC (defaults to `SOLANA_RPC_URL` env or devnet)
- `client.send_rpc(method, params)` — raw JSON-RPC call with retry
- `client.get_balance(pubkey)` — SOL balance in lamports
- `client.get_token_account_balance(ata)` — SPL token balance
- `client.send_transaction(tx_base64)` — submit signed transaction
- `client.get_latest_blockhash` — recent blockhash for transactions
- Retries on rate limit (429) and expired blockhash errors

### Solana::Borsh
- `Borsh.encode_u8/u16/u32/u64(value)` — little-endian integers
- `Borsh.encode_string(str)` — length-prefixed UTF-8
- `Borsh.encode_pubkey(base58)` — 32-byte public key
- `Borsh.encode_bool(val)` — single byte
- `Borsh.encode_vec(items, type)` — length-prefixed array
- `Borsh.decode_*` — corresponding decode methods

### Solana::Transaction
- `Transaction.new` — builder pattern
- `tx.add_instruction(program_id, accounts, data)` — append instruction
- `tx.sign(keypairs, blockhash)` — sign with one or more keypairs
- `tx.serialize` — base64-encoded wire format
- `tx.serialize_partial` — for multi-signer partial signing
- `Transaction.find_pda(program_id, seeds)` — PDA derivation
- `Transaction.anchor_discriminator(name)` — SHA256-based 8-byte discriminator
- `Transaction.on_curve?(pubkey)` — check if pubkey is on Ed25519 curve

### Solana::AuthVerifier
- `AuthVerifier.verify!(message:, signature_b58:, pubkey_b58:, expected_host:, stored_nonce:, nonce_at:, max_age:)` — verifies Ed25519 sig + nonce match + host binding. `expected_host:` is required (OPSEC-018): the message must name it as its opening token, so a signature made for another dApp can't pass. Returns `pubkey_b58` on success, raises `Solana::AuthVerifier::VerificationError` on failure.
- `AuthVerifier::NONCE_MAX_AGE` — default 300 seconds (5 min)
- Pure: no Rails / no session. Host apps adapt their session storage and delegate.

## Design Decisions

- **No Rails dependency** — pure Ruby + ed25519 gem only
- **`Solana::*` namespace** preserved from source app for zero-migration
- **No encryption** — Rails-specific `encrypt`/`from_encrypted` stays in consumer apps
- **`from_base58`** added for loading keypairs from env vars (12-factor friendly)
- **Client defaults** to `SOLANA_RPC_URL` env var or devnet

## Consumer Apps

- **Turf Monster** — keeps `Solana::Config`, `Solana::Vault`, `Solana::Reconciler` app-local (program-specific business logic). Now uses the gem's `Solana::AuthVerifier` + a thin session-adapter shim at `app/services/solana/auth_verifier.rb`.
- **McRitchie Studio** — can use for future Solana features

## Testing

- `ruby -Itest -e 'Dir["test/*_test.rb"].sort.each { |f| require File.expand_path(f) }'` — 43 tests
- **Keypair**: generate, base58 roundtrip, from_bytes, from_json_file, sign, address alias
- **Borsh**: encode/decode roundtrips for u8, u16, u32, u64, string, bool, pubkey, vec, bytes32
- **Transaction**: anchor discriminator (determinism, uniqueness), PDA derivation (determinism, not on curve), on_curve? check, serialization, signer-count validation (OPSEC-017), no instance signer state (OPSEC-043), error cases
- **AuthVerifier**: host-bound verify (OPSEC-018), host mismatch + blank-host + partial-prefix rejection

## Repo

- GitHub: https://github.com/amcritchie/solana-studio
- Install: `gem "solana-studio", "~> 0.4.0"` (RubyGems — consumer apps use this form). The legacy `git:` install form (`gem "solana-studio", git: "...", tag: "v0.4.0"`) still works but should not be used for new code.
- Version: 0.4.2 (gemspec canonical). Renamed from `solana_studio` in v0.4.0 (2026-05-17).
