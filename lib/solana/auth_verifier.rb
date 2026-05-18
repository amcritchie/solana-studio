require "ed25519"

module Solana
  # Verifies a Solana wallet signature against an externally-stored nonce.
  # Pure module — no Rails / no session coupling. Host apps adapt their
  # session storage and call `Solana::AuthVerifier.verify!`.
  #
  # See turf_monster `app/services/solana/auth_verifier.rb` for the Rails
  # session adapter pattern.
  module AuthVerifier
    class VerificationError < StandardError; end

    # Default max nonce age in seconds (5 minutes).
    NONCE_MAX_AGE = 300

    # Verifies that `signature_b58` is a valid Ed25519 signature over
    # `message` made by `pubkey_b58`, AND that the `Nonce: ...` field in
    # the message matches `stored_nonce`, AND that the nonce is not stale.
    #
    # Returns the verified public key (base58 string) on success.
    # Raises Solana::AuthVerifier::VerificationError on any failure.
    #
    # @param message [String] the signed message (must contain `Nonce: <value>`)
    # @param signature_b58 [String] base58-encoded Ed25519 signature
    # @param pubkey_b58 [String] base58-encoded public key
    # @param stored_nonce [String, nil] the nonce the host issued + remembers
    # @param nonce_at [Integer, nil] Unix timestamp when the nonce was issued
    # @param max_age [Integer] seconds before a nonce expires (default 300)
    def self.verify!(message:, signature_b58:, pubkey_b58:, stored_nonce:, nonce_at: nil, max_age: NONCE_MAX_AGE)
      raise VerificationError, "No nonce provided" unless stored_nonce

      if nonce_at && (Time.now.to_i - nonce_at.to_i) > max_age
        raise VerificationError, "Nonce expired"
      end

      sig_bytes = Solana::Keypair.decode_base58(signature_b58)
      pub_bytes = Solana::Keypair.decode_base58(pubkey_b58)

      verify_key = Ed25519::VerifyKey.new(pub_bytes)
      verify_key.verify(sig_bytes, message)

      claimed_nonce = message.match(/Nonce: (\w+)/)&.captures&.first
      raise VerificationError, "Invalid nonce" unless claimed_nonce == stored_nonce

      pubkey_b58
    rescue Ed25519::VerifyError => e
      raise VerificationError, "Signature verification failed: #{e.message}"
    end
  end
end
