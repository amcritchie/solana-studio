# Security Audit — solana-studio

**Date:** 2026-05-17 (pre-publication)
**Scope:** Full code review + `gitleaks` git-history scan + `bundle-audit` dependency check
**Verdict:** **NEEDS FIXES before public RubyGems publication** → **all HIGH + all MEDIUM addressed in v0.4.1** (see "Status after v0.4.1" below)

## Status after v0.4.1

| # | Severity | Issue | Status |
|---|----------|-------|--------|
| 1 | HIGH | Explicit TLS verify_mode + HTTPS-only enforcement | ✅ Fixed — `VERIFY_PEER` + `TLS1_2_VERSION` min; `InsecureRpcUrlError` raised on `http://` non-localhost |
| 2 | HIGH | Borsh decoded-field bounds checking | ✅ Fixed — `MAX_DECODED_FIELD_BYTES = 10MB`; new `decode_string` + `decode_vec` enforce |
| 3 | HIGH | Constant-time nonce comparison | ✅ Fixed — `OpenSSL.fixed_length_secure_compare` via `Solana::AuthVerifier.constant_time_eq?` |
| 4 | MEDIUM | HTTPS-only RPC env validation | ✅ Fixed (subsumed by #1) |
| 5 | MEDIUM | Pubkey/sig length validation + tighter rescue in Transaction | ✅ Fixed — explicit `ED25519_PUBKEY_BYTES` + `ED25519_SIGNATURE_BYTES` checks before `Ed25519::VerifyKey.new` |
| 6 | MEDIUM | Base58 input validation | ✅ Fixed — `Solana::Keypair.decode_base58` raises `ArgumentError` on invalid chars |
| 7 | LOW | Stale docstring path | ✅ Fixed — points at `turf-monster/app/controllers/concerns/solana/session_auth.rb` |
| 8 | LOW | Nonce-deletion docstring | ✅ Fixed — explicit IMPORTANT block in AuthVerifier module docstring |
| 9 | INFO | Default RPC URL is devnet | ⏳ Deferred (documentation polish for README) |
| 10 | INFO | Hardcoded canonical program IDs | ✅ No action needed (correct as-is) |

**Re-audit recommended after v0.4.1** before flipping repo public + pushing to RubyGems.

---

## TL;DR

The crypto primitives are solid: Ed25519 via the reputable `ed25519` gem (Tony Arcieri / Monadic Security), correct PDA derivation, faithful Anchor discriminator computation. Issues are around defensive hardening at the I/O + parsing boundaries: TLS enforcement on RPC URLs, bounds-checking on Borsh decode, constant-time nonce comparison in AuthVerifier, input validation on base58 decode.

This gem is going to be used by strangers to sign + broadcast Solana transactions that move real money. The bar for "ready" is high.

## Scan results

| Tool | Result |
|------|--------|
| `gitleaks` (full history, 14 commits) | ✅ No leaks found |
| `bundle-audit` (gem's Gemfile.lock) | ✅ No vulnerabilities |

## Findings

| # | Severity | Location | Issue | Recommendation |
|---|----------|----------|-------|----------------|
| 1 | HIGH | `lib/solana/client.rb` (HTTP setup) | TLS verify mode not explicitly set on `Net::HTTP`. Modern Ruby defaults to `VERIFY_PEER`, but bare `use_ssl = true` without explicit `verify_mode` leaves it to the global default — which some Ruby builds set differently. | Set explicitly: `http.use_ssl = true; http.verify_mode = OpenSSL::SSL::VERIFY_PEER`. Reject any RPC URL whose scheme isn't `https` (except `http://localhost*` or `http://127.0.0.1*` for local testing). |
| 2 | HIGH | `lib/solana/borsh.rb` (decode helpers) | `decode_u32` (etc.) returns the length verbatim. If consumers use it to decode a vec/string from a malicious RPC response with a declared length of e.g. `4_000_000_000`, the subsequent allocation OOMs the process. | Add a `MAX_FIELD_BYTES` constant (suggest 10MB) and reject decodes that exceed it. Apply to length-prefixed decoders (`decode_string`, `decode_vec`). |
| 3 | HIGH | `lib/solana/auth_verifier.rb` (nonce compare line) | `claimed_nonce == stored_nonce` uses Ruby string `==` — not constant-time, exits early on first byte mismatch. For 16-32-char base58 nonces over a network with ~50ms RTT, this is **not practically exploitable** (~10^28 trials), but it's a standard hygiene rule for crypto code and the fix is one line. | Use `SecureRandom.constant_time_compare(claimed_nonce, stored_nonce)` from `securerandom` (Ruby 3.0+ stdlib). |
| 4 | MEDIUM | `lib/solana/client.rb` (default `SOLANA_RPC_URL` resolution) | No scheme validation on env-var input. If `SOLANA_RPC_URL=http://api.devnet.solana.com` (plaintext), gem proceeds silently. | Reject `http://` unless host is `localhost` / `127.0.0.1`. Document "always use HTTPS for non-local RPC" in README. |
| 5 | MEDIUM | `lib/solana/transaction.rb` (signature verify path) | Bare `rescue` catches all StandardError from `Ed25519::VerifyKey.new` AND `.verify`. If pubkey bytes have wrong length, raises `ArgumentError`, caught + reported as `VerificationError("Signature verification failed")` — masking the actual problem (malformed pubkey, not bad signature). | Tighten to `rescue Ed25519::VerifyError`. Validate `pub_bytes.bytesize == 32` and `sig_bytes.bytesize == 64` *before* calling `VerifyKey.new`. |
| 6 | MEDIUM | `lib/solana/keypair.rb` (`decode_base58`) | No input validation. Invalid base58 chars (`0`, `O`, `I`, `l`) cause `BASE58_ALPHABET.index(c)` → `nil`, then `num * 58 + nil` raises a confusing `TypeError`. Attacker passes garbage → consumer sees a backtrace, not a clean rejection. | Validate per-char before the multiplication loop: `raise ArgumentError, "Invalid base58 character: #{c.inspect}" unless BASE58_ALPHABET.include?(c)`. |
| 7 | LOW | `lib/solana/auth_verifier.rb` (docstring) | References `turf_monster app/services/solana/auth_verifier.rb` as the example adapter — that path no longer exists (post Tier 2 #10 + rename, the adapter lives at `turf-monster/app/controllers/concerns/solana/session_auth.rb`). | Update doc to point at the new file (or generalize to "see consumer apps for session-adapter shims"). |
| 8 | LOW | `lib/solana/auth_verifier.rb` (docstring) | Doesn't explicitly call out that caller **must** delete `stored_nonce` after `verify!` returns (or on failure) to prevent replay. The current design correctly puts this responsibility on the caller, but it needs to be loud. | Add: "**IMPORTANT:** caller MUST invalidate `stored_nonce` immediately after this method returns — successfully or not — to prevent replay. See `turf-monster/app/controllers/concerns/solana/session_auth.rb` for the canonical pattern (`session.delete(:solana_nonce)` BEFORE delegating)." |
| 9 | INFO | `lib/solana/client.rb` (default RPC URL constant) | Hardcoded default to devnet — safe choice (won't accidentally hit mainnet), but document explicitly. | One sentence in README: "Defaults to devnet for safety. Set `SOLANA_RPC_URL=https://api.mainnet-beta.solana.com` (or your paid provider) for mainnet." |
| 10 | INFO | `lib/solana/transaction.rb` (hardcoded program IDs) | TOKEN_PROGRAM, ASSOCIATED_TOKEN_PROGRAM, RENT_SYSVAR are hardcoded — these are canonical Solana addresses and *correct*. Not a bug, just noting they exist as constants. | No change. Document as "intentionally hardcoded — these are immutable canonical Solana program IDs." |

## Pre-publish checklist

Block the RubyGems publish on these:

- [ ] **Fix HIGH 1**: explicit `verify_mode` + HTTPS-only enforcement in `Solana::Client`
- [ ] **Fix HIGH 2**: `MAX_FIELD_BYTES` cap in `Solana::Borsh`
- [ ] **Fix HIGH 3**: constant-time nonce compare in `Solana::AuthVerifier`
- [ ] **Fix MEDIUM 5**: pubkey/sig length validation + tighten rescue in `Solana::Transaction`
- [ ] **Fix MEDIUM 6**: base58 input validation in `Solana::Keypair.decode_base58`
- [ ] **Fix LOW 8**: stronger nonce-deletion docstring in `AuthVerifier`
- [ ] Verify a `LICENSE` file exists (MIT)
- [ ] Test that `ed25519` gem is still maintained (current: 1.4.0, Feb 2024)

OK to defer:
- MEDIUM 4 (HTTPS-only env-var validation) — duplicate of HIGH 1's enforcement layer
- LOW 7 (stale docstring path) — cosmetic
- INFO 9 + 10 — docs polish

## What the audit did NOT cover

- No formal cryptographic review by an outside firm (recommend if this gem starts handling significant TVL through downstream consumers)
- Fuzz testing the Borsh decoder + base58 decoder — would surface more parsing edge cases

## Re-audit cadence

Re-run on every minor version bump or any change to `auth_verifier.rb`, `client.rb`, `borsh.rb`, `keypair.rb`, or `transaction.rb`.
