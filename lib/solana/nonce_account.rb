module Solana
  # Parser for a System-Program durable NONCE account's on-chain data (80 bytes):
  #
  #   version                u32  (offset 0)
  #   state                  u32  (offset 4)   0 = Uninitialized, 1 = Initialized
  #   authority              [32] (offset 8)
  #   stored_nonce/blockhash [32] (offset 40)  ← anchor a tx's recentBlockhash on this
  #   fee_calculator         u64  (offset 72)  lamports_per_signature
  #
  # Used to read the value a durable-nonce-anchored tx must use, and to verify the
  # account is initialized + owned by the expected authority before trusting it.
  class NonceAccount
    UNINITIALIZED = 0
    INITIALIZED   = 1

    attr_reader :version, :state, :authority, :nonce, :lamports_per_signature

    def initialize(version:, state:, authority:, nonce:, lamports_per_signature:)
      @version = version
      @state = state
      @authority = authority # base58
      @nonce = nonce         # base58 — use as the tx recentBlockhash
      @lamports_per_signature = lamports_per_signature
    end

    # `data` is the raw account bytes (binary). Accepts a base64 string too.
    def self.parse(data)
      bytes = data
      if bytes.is_a?(String) && bytes.encoding != Encoding::ASCII_8BIT
        bytes = bytes.b
      end
      # Tolerate a base64-encoded blob (what getAccountInfo returns in data[0]).
      if bytes.bytesize != NonceLength && looks_base64?(bytes)
        require "base64"
        bytes = Base64.decode64(bytes).b
      end
      raise ArgumentError, "nonce account too small (#{bytes.bytesize} bytes, need >= 80)" if bytes.bytesize < 80

      new(
        version:                bytes[0, 4].unpack1("V"),
        state:                  bytes[4, 4].unpack1("V"),
        authority:              Keypair.encode_base58(bytes.byteslice(8, 32)),
        nonce:                  Keypair.encode_base58(bytes.byteslice(40, 32)),
        lamports_per_signature: bytes[72, 8].unpack1("Q<")
      )
    end

    NonceLength = 80

    def self.looks_base64?(str)
      str.bytesize > 80 && str.match?(%r{\A[A-Za-z0-9+/=\r\n]+\z})
    end

    def initialized?
      state == INITIALIZED
    end

    # True when the account is initialized AND its authority matches `expected`
    # (base58). The guard before anchoring any tx on this nonce.
    def authority?(expected)
      initialized? && authority == expected.to_s
    end
  end
end
