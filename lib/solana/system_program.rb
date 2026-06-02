module Solana
  # System Program instruction encoders — the subset needed for DURABLE NONCE
  # accounts (plus CreateAccount, which nonce creation needs). Mirrors the
  # SplToken encoder pattern: each method returns a { program_id, accounts, data }
  # hash for Transaction#add_instruction.
  #
  # A durable nonce lets a transaction stay valid INDEFINITELY (until consumed)
  # instead of expiring with a recent blockhash (~90s) — the canonical pattern
  # for long / async / multi-party signing. A nonce-anchored tx sets
  # recentBlockhash = the account's stored nonce and MUST carry advance_nonce_account
  # as its FIRST instruction, signed by the nonce authority.
  #
  # Instruction data is `u32 LE index` + fields (the System Program's bincode
  # layout). Indices: CreateAccount 0, AdvanceNonceAccount 4, WithdrawNonceAccount 5,
  # InitializeNonceAccount 6, AuthorizeNonceAccount 7. Each encoder is byte-match
  # tested against a known-good @solana/web3.js reference before being trusted.
  module SystemProgram
    module_function

    PROGRAM_ID                 = Transaction::SYSTEM_PROGRAM_ID # 32 zero bytes
    RECENT_BLOCKHASHES_SYSVAR  = Keypair.decode_base58("SysvarRecentB1ockHashes11111111111111111111")
    RENT_SYSVAR                = Transaction::SYSVAR_RENT_PUBKEY
    NONCE_ACCOUNT_LENGTH       = 80

    # CreateAccount (ix 0): fund + allocate `space` bytes owned by `owner`.
    # Both `from` (payer) and `new_account` must sign.
    def create_account(from:, new_account:, lamports:, space:, owner:)
      data = u32(0) + u64(lamports) + u64(space) + normalize(owner)
      {
        program_id: PROGRAM_ID,
        accounts: [
          { pubkey: normalize(from),        is_signer: true, is_writable: true },
          { pubkey: normalize(new_account), is_signer: true, is_writable: true }
        ],
        data: data
      }
    end

    # AdvanceNonceAccount (ix 4): MUST be the first instruction of any tx anchored
    # on this nonce. The `authority` signs it.
    def advance_nonce_account(nonce:, authority:)
      {
        program_id: PROGRAM_ID,
        accounts: [
          { pubkey: normalize(nonce),                     is_signer: false, is_writable: true },
          { pubkey: RECENT_BLOCKHASHES_SYSVAR,            is_signer: false, is_writable: false },
          { pubkey: normalize(authority),                 is_signer: true,  is_writable: false }
        ],
        data: u32(4)
      }
    end

    # WithdrawNonceAccount (ix 5): reclaim lamports from the nonce account.
    def withdraw_nonce_account(nonce:, to:, authority:, lamports:)
      {
        program_id: PROGRAM_ID,
        accounts: [
          { pubkey: normalize(nonce),          is_signer: false, is_writable: true },
          { pubkey: normalize(to),             is_signer: false, is_writable: true },
          { pubkey: RECENT_BLOCKHASHES_SYSVAR, is_signer: false, is_writable: false },
          { pubkey: RENT_SYSVAR,               is_signer: false, is_writable: false },
          { pubkey: normalize(authority),      is_signer: true,  is_writable: false }
        ],
        data: u32(5) + u64(lamports)
      }
    end

    # InitializeNonceAccount (ix 6): turn a freshly-created account into a nonce
    # account owned by `authority`. Paired with create_account in one tx.
    def initialize_nonce_account(nonce:, authority:)
      {
        program_id: PROGRAM_ID,
        accounts: [
          { pubkey: normalize(nonce),          is_signer: false, is_writable: true },
          { pubkey: RECENT_BLOCKHASHES_SYSVAR, is_signer: false, is_writable: false },
          { pubkey: RENT_SYSVAR,               is_signer: false, is_writable: false }
        ],
        data: u32(6) + normalize(authority)
      }
    end

    # AuthorizeNonceAccount (ix 7): rotate the nonce authority. Current authority signs.
    def authorize_nonce_account(nonce:, authority:, new_authority:)
      {
        program_id: PROGRAM_ID,
        accounts: [
          { pubkey: normalize(nonce),     is_signer: false, is_writable: true },
          { pubkey: normalize(authority), is_signer: true,  is_writable: false }
        ],
        data: u32(7) + normalize(new_authority)
      }
    end

    # --- helpers --------------------------------------------------------------

    def u32(n) = [n].pack("V")
    def u64(n) = [n].pack("Q<")

    # base58 string / Keypair / 32-byte binary → 32-byte binary.
    def normalize(value)
      if value.is_a?(Keypair)
        value.public_key_bytes
      elsif value.is_a?(String) && value.bytesize == 32
        value.b
      elsif value.is_a?(String)
        Keypair.decode_base58(value)
      else
        value
      end
    end
  end
end
