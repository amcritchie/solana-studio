require_relative "test_helper"

class TransactionTest < Minitest::Test
  def test_anchor_discriminator
    disc = Solana::Transaction.anchor_discriminator("initialize")
    assert_equal 8, disc.bytesize

    # Should be deterministic
    disc2 = Solana::Transaction.anchor_discriminator("initialize")
    assert_equal disc, disc2
  end

  def test_anchor_discriminator_different_names
    init_disc = Solana::Transaction.anchor_discriminator("initialize")
    deposit_disc = Solana::Transaction.anchor_discriminator("deposit")
    refute_equal init_disc, deposit_disc
  end

  def test_pda_derivation_deterministic
    program_id = Solana::Keypair.generate.public_key_bytes
    seeds = ["vault_state".b]

    pda1, bump1 = Solana::Transaction.find_pda(seeds, program_id)
    pda2, bump2 = Solana::Transaction.find_pda(seeds, program_id)

    assert_equal pda1, pda2
    assert_equal bump1, bump2
    assert_equal 32, pda1.bytesize
    assert_kind_of Integer, bump1
    assert bump1 >= 0 && bump1 <= 255
  end

  def test_pda_is_not_on_curve
    program_id = Solana::Keypair.generate.public_key_bytes
    seeds = ["test_pda".b]

    pda, _ = Solana::Transaction.find_pda(seeds, program_id)
    refute Solana::Transaction.on_curve?(pda), "PDA should not be on the Ed25519 curve"
  end

  def test_on_curve_with_real_pubkey
    kp = Solana::Keypair.generate
    assert Solana::Transaction.on_curve?(kp.public_key_bytes), "Real public key should be on the Ed25519 curve"
  end

  def test_pda_with_base58_program_id
    kp = Solana::Keypair.generate
    address = kp.to_base58
    seeds = ["test".b]

    pda, bump = Solana::Transaction.find_pda(seeds, address)
    assert_equal 32, pda.bytesize
    assert bump >= 0 && bump <= 255
  end

  def test_pda_with_multiple_seeds
    program_id = Solana::Keypair.generate.public_key_bytes
    user_key = Solana::Keypair.generate.public_key_bytes
    seeds = ["user_account".b, user_key]

    pda, bump = Solana::Transaction.find_pda(seeds, program_id)
    assert_equal 32, pda.bytesize
    refute Solana::Transaction.on_curve?(pda)
  end

  def test_system_program_id_is_zero_bytes
    assert_equal "\x00" * 32, Solana::Transaction::SYSTEM_PROGRAM_ID
  end

  def test_token_program_id_decodes
    assert_equal 32, Solana::Transaction::TOKEN_PROGRAM_ID.bytesize
  end

  def test_transaction_requires_blockhash
    tx = Solana::Transaction.new
    kp = Solana::Keypair.generate
    tx.add_signer(kp)
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [{ pubkey: kp.public_key_bytes, is_signer: true, is_writable: true }],
      data: "\x00"
    )

    assert_raises(RuntimeError) { tx.serialize }
  end

  def test_transaction_requires_signers
    tx = Solana::Transaction.new
    blockhash = Solana::Keypair.encode_base58("\x01" * 32)
    tx.set_recent_blockhash(blockhash)
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [],
      data: "\x00"
    )

    assert_raises(RuntimeError) { tx.serialize }
  end

  def test_transaction_serializes
    tx = Solana::Transaction.new
    kp = Solana::Keypair.generate
    blockhash = Solana::Keypair.encode_base58("\x01" * 32)

    tx.set_recent_blockhash(blockhash)
    tx.add_signer(kp)
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [{ pubkey: kp.public_key_bytes, is_signer: true, is_writable: true }],
      data: "\x00"
    )

    serialized = tx.serialize
    assert serialized.bytesize > 0

    # Should also work as base64
    b64 = tx.serialize_base64
    assert b64.is_a?(String)
    assert b64.length > 0
  end

  # OPSEC-017: serialize must reject a transaction whose account list requires
  # more signatures than there are signers.
  def test_serialize_raises_on_signer_count_mismatch
    tx = Solana::Transaction.new
    kp = Solana::Keypair.generate
    other = Solana::Keypair.generate
    tx.set_recent_blockhash(Solana::Keypair.encode_base58("\x01" * 32))
    tx.add_signer(kp)
    # `other` is marked is_signer in the instruction but never added as a signer.
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [
        { pubkey: kp.public_key_bytes, is_signer: true, is_writable: true },
        { pubkey: other.public_key_bytes, is_signer: true, is_writable: false }
      ],
      data: "\x00"
    )
    err = assert_raises(RuntimeError) { tx.serialize }
    assert_match(/Signer count mismatch/, err.message)
  end

  # OPSEC-017: serialize_partial is the legitimate multi-signer path — a local
  # signer plus an additional (client-side) signer covering every required slot.
  def test_serialize_partial_happy_path
    tx = Solana::Transaction.new
    kp = Solana::Keypair.generate
    other = Solana::Keypair.generate
    tx.set_recent_blockhash(Solana::Keypair.encode_base58("\x01" * 32))
    tx.add_signer(kp)
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [
        { pubkey: kp.public_key_bytes, is_signer: true, is_writable: true },
        { pubkey: other.public_key_bytes, is_signer: true, is_writable: false }
      ],
      data: "\x00"
    )
    serialized = tx.serialize_partial(additional_signers: [other.public_key_bytes])
    assert serialized.bytesize > 0
  end

  # OPSEC-017: serialize_partial must reject a required signer that is neither
  # a local signer nor an additional signer — otherwise its slot is silently
  # zero-filled and the half-signed TX is still broadcastable.
  def test_serialize_partial_raises_on_uncovered_signer
    tx = Solana::Transaction.new
    kp = Solana::Keypair.generate
    other = Solana::Keypair.generate
    tx.set_recent_blockhash(Solana::Keypair.encode_base58("\x01" * 32))
    tx.add_signer(kp)
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [
        { pubkey: kp.public_key_bytes, is_signer: true, is_writable: true },
        { pubkey: other.public_key_bytes, is_signer: true, is_writable: false }
      ],
      data: "\x00"
    )
    err = assert_raises(RuntimeError) { tx.serialize_partial }
    assert_match(/Signer count mismatch/, err.message)
  end

  # OPSEC-043: serialize_partial must not stash signer state on the instance.
  def test_serialize_partial_keeps_no_instance_signer_state
    tx = Solana::Transaction.new
    kp = Solana::Keypair.generate
    other = Solana::Keypair.generate
    tx.set_recent_blockhash(Solana::Keypair.encode_base58("\x01" * 32))
    tx.add_signer(kp)
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [
        { pubkey: kp.public_key_bytes, is_signer: true, is_writable: true },
        { pubkey: other.public_key_bytes, is_signer: true, is_writable: false }
      ],
      data: "\x00"
    )
    tx.serialize_partial(additional_signers: [other.public_key_bytes])
    refute tx.instance_variable_defined?(:@_additional_signers),
           "serialize_partial must not retain signer state in an instance variable"
  end

  # --- cosign_wire (Phantom-first inverse-order cosign) ---------------------

  # Build a fully-UNSIGNED two-signer wire tx: `payer` (fee payer) and `user`
  # are both required signers but neither signs locally — both are passed as
  # additional_signers, leaving both slots zero. Mirrors the new
  # build_enter_contest: admin is fee payer, both slots empty for client-then-
  # server cosign.
  def build_unsigned_two_signer_wire(payer, user)
    tx = Solana::Transaction.new
    tx.set_recent_blockhash(Solana::Keypair.encode_base58("\x07" * 32))
    tx.add_instruction(
      program_id: Solana::Transaction::SYSTEM_PROGRAM_ID,
      accounts: [
        { pubkey: payer.public_key_bytes, is_signer: true, is_writable: true },
        { pubkey: user.public_key_bytes,  is_signer: true, is_writable: false }
      ],
      data: "\x09"
    )
    # No local signers — keyless build, payer ordered first so it's the fee payer.
    tx.serialize_partial(additional_signers: [payer.public_key_bytes, user.public_key_bytes])
  end

  # Pull the [sig_count, sigs_start, message_start] frame out of a wire tx.
  def wire_frame(wire)
    count, cursor = Solana::Transaction.read_compact_u16(wire, 0)
    [count, cursor, cursor + count * 64]
  end

  def slot_bytes(wire, index)
    _, sigs_start, _ = wire_frame(wire)
    wire.byteslice(sigs_start + index * 64, 64)
  end

  def signer_slot_index(wire, signer)
    count, _, message_start = wire_frame(wire)
    acct_cursor = message_start + 3
    _, acct_cursor = Solana::Transaction.read_compact_u16(wire, acct_cursor)
    count.times.find { |i| wire.byteslice(acct_cursor + i * 32, 32) == signer.public_key_bytes.b }
  end

  def message_bytes(wire)
    _, _, message_start = wire_frame(wire)
    wire.byteslice(message_start, wire.bytesize - message_start)
  end

  ZERO64 = ("\x00" * 64).b

  def test_cosign_wire_fills_correct_slot
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user)

    user_idx = signer_slot_index(wire, user)
    refute_nil user_idx, "user must be a required signer"
    assert_equal ZERO64, slot_bytes(wire, user_idx), "user slot starts empty"

    patched = Solana::Transaction.cosign_wire(wire, signer: user, require_complete: false)

    # The USER's slot is now filled with a valid signature over the message.
    sig = slot_bytes(patched, user_idx)
    refute_equal ZERO64, sig
    assert user.verify_key.verify(sig, message_bytes(patched)), "user's signature must verify over the message"
  end

  def test_cosign_wire_leaves_other_signature_and_message_untouched
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user)

    # Phantom (user) signs FIRST.
    after_user = Solana::Transaction.cosign_wire(wire, signer: user, require_complete: false)
    payer_idx  = signer_slot_index(after_user, payer)
    user_idx   = signer_slot_index(after_user, user)
    user_sig_before = slot_bytes(after_user, user_idx)
    msg_before      = message_bytes(after_user)

    # Server (payer) cosigns SECOND.
    final = Solana::Transaction.cosign_wire(after_user, signer: payer)

    # The user's (Phantom's) signature is byte-for-byte unchanged.
    assert_equal user_sig_before, slot_bytes(final, user_idx),
                 "cosigning the payer must not touch the user's signature"
    # The message bytes are byte-for-byte unchanged.
    assert_equal msg_before, message_bytes(final),
                 "cosigning must not alter the message Phantom signed"
    # Payer's slot is now a valid signature.
    assert payer.verify_key.verify(slot_bytes(final, payer_idx), message_bytes(final))
  end

  def test_cosign_wire_yields_two_valid_signatures
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user)

    final = Solana::Transaction.cosign_wire(
      Solana::Transaction.cosign_wire(wire, signer: user, require_complete: false),
      signer: payer
    )

    count, _, _ = wire_frame(final)
    assert_equal 2, count
    msg = message_bytes(final)
    count.times do |i|
      refute_equal ZERO64, slot_bytes(final, i), "slot #{i} must be filled"
    end
    assert payer.verify_key.verify(slot_bytes(final, signer_slot_index(final, payer)), msg)
    assert user.verify_key.verify(slot_bytes(final, signer_slot_index(final, user)), msg)
  end

  def test_cosign_wire_refuses_to_clobber_existing_signature
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user)

    after_user = Solana::Transaction.cosign_wire(wire, signer: user, require_complete: false)
    # Trying to cosign as `user` AGAIN must refuse — its slot is already full.
    err = assert_raises(RuntimeError) { Solana::Transaction.cosign_wire(after_user, signer: user) }
    assert_match(/already holds a signature/, err.message)
  end

  def test_cosign_wire_rejects_non_signer
    payer    = Solana::Keypair.generate
    user     = Solana::Keypair.generate
    stranger = Solana::Keypair.generate
    wire     = build_unsigned_two_signer_wire(payer, user)

    err = assert_raises(RuntimeError) { Solana::Transaction.cosign_wire(wire, signer: stranger) }
    assert_match(/not a required signer/, err.message)
  end

  # OPSEC-017 post-condition: cosigning only ONE of two required slots must not
  # be mistaken for complete — the method asserts every slot non-zero AFTER its
  # own write, so a single cosign of a 2-signer tx leaves the OTHER slot empty
  # and the method that wrote the LAST missing slot is the one that passes.
  # Here we verify the half-signed result still has an empty slot (sanity for
  # the off-by-one guard: the right slot, and only it, got filled).
  def test_cosign_wire_only_target_slot_filled_off_by_one_guard
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user)

    after_user = Solana::Transaction.cosign_wire(wire, signer: user, require_complete: false)
    user_idx   = signer_slot_index(after_user, user)
    payer_idx  = signer_slot_index(after_user, payer)

    refute_equal user_idx, payer_idx
    refute_equal ZERO64, slot_bytes(after_user, user_idx), "user slot filled"
    assert_equal ZERO64, slot_bytes(after_user, payer_idx), "payer slot still empty (no off-by-one bleed)"
  end

  def test_cosign_wire_rejects_malformed_header_count_mismatch
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user).dup

    # Corrupt the message header's numRequiredSignatures to 1 (sig array still 2)
    _, _, message_start = wire_frame(wire)
    wire.setbyte(message_start, 1)
    err = assert_raises(RuntimeError) { Solana::Transaction.cosign_wire(wire, signer: user) }
    assert_match(/numRequiredSignatures/, err.message)
  end

  def test_cosign_wire_base64_roundtrip
    require "base64"
    payer = Solana::Keypair.generate
    user  = Solana::Keypair.generate
    wire  = build_unsigned_two_signer_wire(payer, user)
    b64   = Base64.strict_encode64(wire)

    patched_b64 = Solana::Transaction.cosign_wire_base64(b64, signer: user, require_complete: false)
    patched     = Base64.decode64(patched_b64)
    user_idx    = signer_slot_index(patched, user)
    assert user.verify_key.verify(slot_bytes(patched, user_idx), message_bytes(patched))
  end
end
