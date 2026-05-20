require_relative "test_helper"

class AuthVerifierTest < Minitest::Test
  HOST = "turf.example.com"

  # Build a host-bound, nonce-carrying message and sign it with a fresh key.
  def signed_message(host: HOST, nonce: "abc123XYZ")
    kp = Solana::Keypair.generate
    message = "#{host} wants to sign in with your Solana account:\n\nNonce: #{nonce}"
    {
      message: message,
      signature_b58: Solana::Keypair.encode_base58(kp.sign(message)),
      pubkey_b58: kp.to_base58,
      nonce: nonce
    }
  end

  def test_verify_accepts_a_host_bound_message
    m = signed_message
    result = Solana::AuthVerifier.verify!(
      message: m[:message], signature_b58: m[:signature_b58], pubkey_b58: m[:pubkey_b58],
      expected_host: HOST, stored_nonce: m[:nonce]
    )
    assert_equal m[:pubkey_b58], result
  end

  # OPSEC-018: a signature over a message bound to a different host must be
  # rejected even when the nonce matches.
  def test_verify_rejects_host_mismatch
    m = signed_message
    err = assert_raises(Solana::AuthVerifier::VerificationError) do
      Solana::AuthVerifier.verify!(
        message: m[:message], signature_b58: m[:signature_b58], pubkey_b58: m[:pubkey_b58],
        expected_host: "evil.example.com", stored_nonce: m[:nonce]
      )
    end
    assert_match(/not bound to host/, err.message)
  end

  def test_verify_requires_a_non_blank_expected_host
    m = signed_message
    assert_raises(Solana::AuthVerifier::VerificationError) do
      Solana::AuthVerifier.verify!(
        message: m[:message], signature_b58: m[:signature_b58], pubkey_b58: m[:pubkey_b58],
        expected_host: "", stored_nonce: m[:nonce]
      )
    end
  end

  # The host match is exact — a host that is a prefix of the message's host
  # must not pass (the trailing space in the check guards against this).
  def test_verify_rejects_partial_host_prefix
    m = signed_message(host: "turf.example.com")
    assert_raises(Solana::AuthVerifier::VerificationError) do
      Solana::AuthVerifier.verify!(
        message: m[:message], signature_b58: m[:signature_b58], pubkey_b58: m[:pubkey_b58],
        expected_host: "turf.example", stored_nonce: m[:nonce]
      )
    end
  end
end
