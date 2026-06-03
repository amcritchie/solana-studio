require_relative "test_helper"

# Byte-match safety gate for the System-Program nonce encoders. The expected
# bytes are the EXACT layout @solana/web3.js emits (u32 LE ix index + fields) —
# a drift here would sign a malformed nonce op, so each is asserted literally.
class SystemProgramTest < Minitest::Test
  SP = Solana::SystemProgram

  def setup
    @authority = Solana::Keypair.generate
    @auth_b = @authority.public_key_bytes
    @nonce  = Solana::Keypair.generate
    @payer  = Solana::Keypair.generate
  end

  def test_advance_nonce_account_bytes_and_metas
    ix = SP.advance_nonce_account(nonce: @nonce.to_base58, authority: @authority.to_base58)
    # data = u32 LE index 4
    assert_equal "\x04\x00\x00\x00".b, ix[:data]
    assert_equal Solana::Transaction::SYSTEM_PROGRAM_ID, ix[:program_id]
    # accounts: nonce(w) , RecentBlockhashes(r), authority(signer,r)
    assert_equal 3, ix[:accounts].length
    assert_equal @nonce.public_key_bytes, ix[:accounts][0][:pubkey]
    assert ix[:accounts][0][:is_writable]
    refute ix[:accounts][0][:is_signer]
    assert_equal SP::RECENT_BLOCKHASHES_SYSVAR, ix[:accounts][1][:pubkey]
    assert_equal @auth_b, ix[:accounts][2][:pubkey]
    assert ix[:accounts][2][:is_signer]
    refute ix[:accounts][2][:is_writable]
  end

  def test_initialize_nonce_account_bytes_and_metas
    ix = SP.initialize_nonce_account(nonce: @nonce, authority: @authority)
    # data = u32 LE index 6 + authority pubkey (32)
    assert_equal ("\x06\x00\x00\x00".b + @auth_b), ix[:data]
    assert_equal 36, ix[:data].bytesize
    assert_equal 3, ix[:accounts].length
    assert ix[:accounts][0][:is_writable]                       # nonce
    assert_equal SP::RECENT_BLOCKHASHES_SYSVAR, ix[:accounts][1][:pubkey]
    assert_equal SP::RENT_SYSVAR, ix[:accounts][2][:pubkey]
  end

  def test_create_account_bytes
    ix = SP.create_account(from: @payer, new_account: @nonce, lamports: 1_447_680,
                           space: SP::NONCE_ACCOUNT_LENGTH, owner: Solana::Transaction::SYSTEM_PROGRAM_ID)
    expected = "\x00\x00\x00\x00".b + [1_447_680].pack("Q<") + [80].pack("Q<") + ("\x00".b * 32)
    assert_equal expected, ix[:data]
    assert ix[:accounts][0][:is_signer] && ix[:accounts][0][:is_writable] # payer
    assert ix[:accounts][1][:is_signer] && ix[:accounts][1][:is_writable] # new account
  end

  def test_withdraw_nonce_account_bytes
    ix = SP.withdraw_nonce_account(nonce: @nonce, to: @payer, authority: @authority, lamports: 1_000_000)
    assert_equal ("\x05\x00\x00\x00".b + [1_000_000].pack("Q<")), ix[:data]
    assert_equal 5, ix[:accounts].length
    assert ix[:accounts].last[:is_signer] # authority
  end

  def test_authorize_nonce_account_bytes
    new_auth = Solana::Keypair.generate
    ix = SP.authorize_nonce_account(nonce: @nonce, authority: @authority, new_authority: new_auth)
    assert_equal ("\x07\x00\x00\x00".b + new_auth.public_key_bytes), ix[:data]
    assert ix[:accounts][1][:is_signer] # current authority signs
  end

  # --- NonceAccount.parse round-trip ---------------------------------------

  def test_nonce_account_parse
    authority = Solana::Keypair.generate
    stored    = Solana::Keypair.generate # any 32 bytes stand in for the stored nonce
    blob = [1].pack("V") +                       # version
           [1].pack("V") +                       # state = Initialized
           authority.public_key_bytes +          # authority [32]
           stored.public_key_bytes +             # stored nonce [32]
           [5000].pack("Q<")                     # lamports_per_signature
    assert_equal 80, blob.bytesize

    na = Solana::NonceAccount.parse(blob)
    assert na.initialized?
    assert_equal authority.to_base58, na.authority
    assert_equal stored.to_base58, na.nonce
    assert_equal 5000, na.lamports_per_signature
    assert na.authority?(authority.to_base58)
    refute na.authority?(Solana::Keypair.generate.to_base58)
  end

  def test_nonce_account_parse_uninitialized
    blob = [1].pack("V") + [0].pack("V") + ("\x00".b * 32) + ("\x00".b * 32) + [0].pack("Q<")
    na = Solana::NonceAccount.parse(blob)
    refute na.initialized?
    refute na.authority?(Solana::Keypair.generate.to_base58)
  end

  # The advance ix actually serializes into a tx as instruction #0 (proves it
  # composes with Transaction + the keyless build path).
  def test_advance_composes_into_a_partial_tx
    tx = Solana::Transaction.new
    tx.set_recent_blockhash(@nonce.to_base58) # nonce value stands in as the "blockhash"
    adv = SP.advance_nonce_account(nonce: @nonce, authority: @authority)
    tx.add_instruction(program_id: adv[:program_id], accounts: adv[:accounts], data: adv[:data])
    b64 = tx.serialize_partial_base64(additional_signers: [@authority.to_base58])
    assert b64.is_a?(String) && !b64.empty?
  end
end
