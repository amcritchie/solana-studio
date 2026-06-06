require "digest"

module Solana
  class Transaction
    SYSTEM_PROGRAM_ID = "\x00" * 32
    TOKEN_PROGRAM_ID = Keypair.decode_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    ASSOCIATED_TOKEN_PROGRAM_ID = Keypair.decode_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    SYSVAR_RENT_PUBKEY = Keypair.decode_base58("SysvarRent111111111111111111111111111111111")

    attr_reader :instructions, :signers

    def initialize
      @instructions = []
      @signers = []
      @recent_blockhash = nil
    end

    # Compute Anchor instruction discriminator: SHA256("global:<name>")[0..7]
    def self.anchor_discriminator(name)
      Digest::SHA256.digest("global:#{name}")[0, 8]
    end

    # Derive PDA (Program Derived Address)
    def self.find_pda(seeds, program_id_bytes)
      program_id_bytes = Keypair.decode_base58(program_id_bytes) if program_id_bytes.is_a?(String) && program_id_bytes.length != 32

      255.downto(0) do |bump|
        candidate_seeds = seeds + [[bump].pack("C")]
        begin
          hash_input = candidate_seeds.map { |s| s.is_a?(String) ? s.b : s.pack("C*") }.join
          hash_input += program_id_bytes.b
          hash_input += "ProgramDerivedAddress".b

          candidate = Digest::SHA256.digest(hash_input)

          # Check if the point is on the Ed25519 curve — PDA must NOT be on curve
          unless on_curve?(candidate)
            return [candidate, bump]
          end
        rescue
          next
        end
      end
      raise "Could not find PDA"
    end

    def set_recent_blockhash(blockhash)
      @recent_blockhash = Keypair.decode_base58(blockhash)
      self
    end

    def add_signer(keypair)
      @signers << keypair
      self
    end

    def add_instruction(program_id:, accounts:, data:)
      program_id_bytes = normalize_pubkey(program_id)
      @instructions << {
        program_id: program_id_bytes,
        accounts: accounts.map { |a|
          {
            pubkey: normalize_pubkey(a[:pubkey]),
            is_signer: a[:is_signer] || false,
            is_writable: a[:is_writable] || false
          }
        },
        data: data.is_a?(String) ? data.b : data.pack("C*")
      }
      self
    end

    # Serialize and sign the transaction
    def serialize
      raise "No blockhash set" unless @recent_blockhash
      raise "No signers" if @signers.empty?
      raise "No instructions" if @instructions.empty?

      # Collect all unique accounts in order
      account_keys = collect_account_keys
      num_required_signatures = count_required_signatures(account_keys)
      num_readonly_signed = count_readonly_signed(account_keys)
      num_readonly_unsigned = count_readonly_unsigned(account_keys)

      # OPSEC-017: the message header declares num_required_signatures, but we
      # only write @signers.length signatures. A mismatch produces a malformed
      # payload — fail loudly here instead of emitting a silently-broken TX.
      if @signers.length != num_required_signatures
        raise "Signer count mismatch: #{@signers.length} signer(s) provided, " \
              "#{num_required_signatures} required by the account list"
      end

      # Build message
      message = build_message(account_keys, num_required_signatures, num_readonly_signed, num_readonly_unsigned)

      # Sign message
      signatures = @signers.map { |signer| signer.sign(message) }

      # Compact-array encode signature count + signatures + message
      compact_u16(signatures.length) + signatures.join.b + message
    end

    def serialize_base64
      require "base64"
      Base64.strict_encode64(serialize)
    end

    # Serialize with partial signing — signs with available signers, leaves
    # zero-byte placeholders for additional_signers that must sign client-side.
    # additional_signers: array of pubkey bytes (32-byte strings) that will sign later.
    def serialize_partial(additional_signers: [])
      raise "No blockhash set" unless @recent_blockhash
      # A fully KEYLESS build (zero local signers, all slots filled by external
      # additional_signers) is legitimate for multi-party coordination where the
      # server never holds a key — only require SOME signer is accounted for.
      raise "No signers" if @signers.empty? && additional_signers.empty?
      raise "No instructions" if @instructions.empty?

      # OPSEC-043: keep additional signers in a local — never an instance ivar.
      # A Transaction shared across threads/requests must not leak signer state
      # between partial-sign flows.
      normalized_additional = additional_signers.map { |pk| normalize_pubkey(pk) }

      account_keys = collect_account_keys(normalized_additional)
      num_required_signatures = count_required_signatures(account_keys)
      num_readonly_signed = count_readonly_signed(account_keys)
      num_readonly_unsigned = count_readonly_unsigned(account_keys)

      # OPSEC-017: every required signature slot must be covered by a local
      # signer (signed now) or an additional signer (signs client-side later).
      # Otherwise a slot is silently zero-filled and the half-signed TX is
      # still broadcastable.
      provided = @signers.length + normalized_additional.length
      if provided != num_required_signatures
        raise "Signer count mismatch: #{provided} provided " \
              "(#{@signers.length} local + #{normalized_additional.length} additional), " \
              "#{num_required_signatures} required by the account list"
      end

      message = build_message(account_keys, num_required_signatures, num_readonly_signed, num_readonly_unsigned)

      # Build ordered signature slots matching the account key order
      signer_map = {}
      @signers.each { |s| signer_map[s.public_key_bytes] = s.sign(message) }

      signatures = account_keys.select { |_, meta| meta[:is_signer] }.map do |pk, _|
        signer_map[pk] || ("\x00" * 64).b  # zero placeholder for an additional (client-side) signer
      end

      compact_u16(signatures.length) + signatures.join.b + message
    end

    def serialize_partial_base64(additional_signers: [])
      require "base64"
      Base64.strict_encode64(serialize_partial(additional_signers: additional_signers))
    end

    # Add one signature to an already-(partially-)signed wire transaction WITHOUT
    # rebuilding it. This is the inverse-order cosign: a client wallet (Phantom)
    # signs FIRST and returns the wire bytes with its slot filled and the other
    # slots zero; the server then drops its own signature into the correct slot.
    #
    # Why this exists (Phantom "could be malicious" banner fix): when the SERVER
    # pre-signs and Phantom signs SECOND, Phantom's Lighthouse heuristics flag
    # the multi-signer ordering. Flipping the order — Phantom signs the
    # fully-unsigned tx first, server cosigns after — clears that rule. The
    # server can't rebuild-and-resign (that would change the message bytes and
    # invalidate Phantom's signature), so it must surgically patch the existing
    # wire payload.
    #
    # Pure Ruby, no RPC. Parses the compact-u16 signature count + the message
    # header, locates `signer` in the account-key list, asserts that slot is
    # still zero (never clobber a real signature), signs the EXACT message bytes
    # Phantom signed, and writes the 64-byte signature into that slot. Re-asserts
    # OPSEC-017 afterwards: every one of the numRequiredSignatures slots must be
    # non-zero (the tx is now fully signed and broadcastable).
    #
    # signed_wire_bytes : String (binary) — the wire-format tx (sig count + sigs + message)
    # signer:           : Solana::Keypair — the cosigner (e.g. the admin keypair)
    # require_complete: : when true (default) re-assert OPSEC-017 AFTER the write —
    #   every one of the numRequiredSignatures slots must be non-zero, i.e. this
    #   cosigner is the LAST one and the tx is now fully broadcastable. The
    #   turf-monster server cosign is always the final signer, so it leaves this
    #   on. Pass false for an intermediate cosign in a 3+-signer chain.
    # Returns the patched wire bytes (binary String). Phantom's signature and the
    # message bytes are left byte-for-byte untouched.
    def self.cosign_wire(signed_wire_bytes, signer:, require_complete: true)
      bytes = signed_wire_bytes.b.dup
      cursor = 0

      # 1. Compact-u16 signature count.
      sig_count, cursor = read_compact_u16(bytes, cursor)
      raise "cosign_wire: zero signatures in wire payload" if sig_count.zero?

      sigs_start = cursor
      sigs_len = sig_count * 64
      raise "cosign_wire: truncated signature array" if bytes.bytesize < sigs_start + sigs_len
      message_start = sigs_start + sigs_len

      # 2. Message header — first byte is numRequiredSignatures. It MUST equal the
      # signature-array length (a well-formed message reserves exactly one slot
      # per declared signer). Guard against an off-by-one / malformed payload.
      num_required = bytes.getbyte(message_start)
      raise "cosign_wire: empty message" if num_required.nil?
      unless num_required == sig_count
        raise "cosign_wire: header numRequiredSignatures=#{num_required} != " \
              "signature slots=#{sig_count} (malformed wire payload)"
      end

      # 3. Account keys. Header is 3 bytes, then a compact-u16 account count,
      # then `count` * 32-byte keys. The first `num_required` account keys are
      # the signer slots, in the SAME order as the signature array.
      acct_cursor = message_start + 3
      account_count, acct_cursor = read_compact_u16(bytes, acct_cursor)
      raise "cosign_wire: account count #{account_count} < required signers #{num_required}" if account_count < num_required

      target = signer.public_key_bytes.b
      slot_index = nil
      num_required.times do |i|
        key = bytes.byteslice(acct_cursor + (i * 32), 32)
        if key == target
          slot_index = i
          break
        end
      end
      raise "cosign_wire: signer #{signer.address} is not a required signer of this transaction" if slot_index.nil?

      # 4. The target slot must be empty (all-zero). Never clobber a signature
      # that's already there (Phantom's, or a prior cosigner's).
      slot_offset = sigs_start + (slot_index * 64)
      existing = bytes.byteslice(slot_offset, 64)
      unless existing == ("\x00" * 64).b
        raise "cosign_wire: slot #{slot_index} for #{signer.address} already holds a signature — refusing to clobber"
      end

      # 5. Sign the EXACT message bytes Phantom signed and write the signature in.
      message = bytes.byteslice(message_start, bytes.bytesize - message_start)
      signature = signer.sign(message)
      raise "cosign_wire: signature is not 64 bytes" unless signature.bytesize == 64
      bytes[slot_offset, 64] = signature.b

      # 6. OPSEC-017 post-condition (when require_complete): the tx must now be
      # fully signed — every one of the num_required slots non-zero. A leftover
      # zero slot means another signer is still missing and the payload is not
      # broadcastable. The server cosign is the last signer, so it asserts this;
      # an intermediate cosign in a 3+-signer chain passes require_complete:false.
      if require_complete
        num_required.times do |i|
          off = sigs_start + (i * 64)
          if bytes.byteslice(off, 64) == ("\x00" * 64).b
            raise "cosign_wire: slot #{i} is still empty after cosign — " \
                  "transaction needs #{num_required} signatures and is not yet complete"
          end
        end
      end

      bytes
    end

    # Convenience: cosign a base64 wire tx, return base64.
    def self.cosign_wire_base64(signed_wire_base64, signer:, require_complete: true)
      require "base64"
      patched = cosign_wire(Base64.decode64(signed_wire_base64), signer: signer, require_complete: require_complete)
      Base64.strict_encode64(patched)
    end

    # Decode a compact-u16 (ShortVec) starting at `offset`. Returns [value, next_offset].
    def self.read_compact_u16(bytes, offset)
      value = 0
      shift = 0
      loop do
        byte = bytes.getbyte(offset)
        raise "read_compact_u16: ran off the end of the buffer" if byte.nil?
        offset += 1
        value |= (byte & 0x7F) << shift
        break if (byte & 0x80).zero?
        shift += 7
        raise "read_compact_u16: value too large" if shift > 21
      end
      [value, offset]
    end

    private

    def normalize_pubkey(key)
      if key.is_a?(String) && key.bytesize == 32
        key.b
      elsif key.is_a?(String)
        Keypair.decode_base58(key)
      elsif key.is_a?(Keypair)
        key.public_key_bytes
      else
        key
      end
    end

    def collect_account_keys(additional_signers = [])
      keys = {}

      # Fee payer (first signer) is always first. In a fully-keyless build there
      # are no local @signers, so fall back to the first ADDITIONAL signer
      # (callers order additional_signers with the fee payer first). The
      # serialize/serialize_partial guards guarantee at least one is present.
      fee_payer = @signers.first&.public_key_bytes || additional_signers.first
      keys[fee_payer] = { is_signer: true, is_writable: true }

      # Other signers (drop(1) is nil-safe when @signers is empty — keyless build)
      @signers.drop(1).each do |signer|
        pk = signer.public_key_bytes
        keys[pk] ||= { is_signer: true, is_writable: false }
        keys[pk][:is_signer] = true
      end

      # Additional signers (for partial signing — not in @signers but must be marked as signer)
      additional_signers.each do |pk|
        keys[pk] ||= { is_signer: true, is_writable: false }
        keys[pk][:is_signer] = true
      end

      # Instruction accounts
      @instructions.each do |ix|
        ix[:accounts].each do |account|
          pk = account[:pubkey]
          keys[pk] ||= { is_signer: false, is_writable: false }
          keys[pk][:is_signer] ||= account[:is_signer]
          keys[pk][:is_writable] ||= account[:is_writable]
        end
        # Program ID (always readonly, unsigned)
        keys[ix[:program_id]] ||= { is_signer: false, is_writable: false }
      end

      # Sort: signer+writable, signer+readonly, non-signer+writable, non-signer+readonly
      # Fee payer stays first
      sorted = keys.to_a.sort_by do |pk, meta|
        if pk == fee_payer
          [0, 0, 0]
        elsif meta[:is_signer] && meta[:is_writable]
          [0, 0, 1]
        elsif meta[:is_signer]
          [0, 1, 0]
        elsif meta[:is_writable]
          [1, 0, 0]
        else
          [1, 1, 0]
        end
      end

      sorted
    end

    def count_required_signatures(account_keys)
      account_keys.count { |_, meta| meta[:is_signer] }
    end

    def count_readonly_signed(account_keys)
      account_keys.count { |_, meta| meta[:is_signer] && !meta[:is_writable] }
    end

    def count_readonly_unsigned(account_keys)
      account_keys.count { |_, meta| !meta[:is_signer] && !meta[:is_writable] }
    end

    def build_message(account_keys, num_required_signatures, num_readonly_signed, num_readonly_unsigned)
      msg = "".b

      # Header
      msg << [num_required_signatures, num_readonly_signed, num_readonly_unsigned].pack("CCC")

      # Account keys (compact array)
      msg << compact_u16(account_keys.length)
      account_keys.each { |pk, _| msg << pk.b }

      # Recent blockhash
      msg << @recent_blockhash.b

      # Instructions (compact array)
      msg << compact_u16(@instructions.length)
      key_index = account_keys.map { |pk, _| pk }.each_with_index.to_h

      @instructions.each do |ix|
        msg << [key_index[ix[:program_id]]].pack("C")
        msg << compact_u16(ix[:accounts].length)
        ix[:accounts].each do |account|
          msg << [key_index[account[:pubkey]]].pack("C")
        end
        msg << compact_u16(ix[:data].bytesize)
        msg << ix[:data]
      end

      msg
    end

    def compact_u16(value)
      bytes = []
      loop do
        byte = value & 0x7F
        value >>= 7
        byte |= 0x80 if value > 0
        bytes << byte
        break if value == 0
      end
      bytes.pack("C*")
    end

    # Check if 32 bytes represent a valid Ed25519 public key (point on curve).
    # PDA addresses must NOT be on the curve.
    ED25519_P = (2**255) - 19
    ED25519_D = (-121_665 * 121_666.pow(ED25519_P - 2, ED25519_P)) % ED25519_P

    def self.on_curve?(bytes)
      bytes = bytes.b
      # Decode y-coordinate (little-endian, clear high bit)
      y = bytes.unpack("C*").each_with_index.sum { |b, i| b * (256**i) }
      y &= (2**255) - 1 # clear sign bit
      return false if y >= ED25519_P

      # Check if x^2 = (y^2 - 1) / (d*y^2 + 1) has a square root mod p
      y2 = y.pow(2, ED25519_P)
      u = (y2 - 1) % ED25519_P
      v = (ED25519_D * y2 + 1) % ED25519_P

      # Compute candidate: x = (u/v)^((p+3)/8) mod p
      v_inv = v.pow(ED25519_P - 2, ED25519_P)
      x2 = (u * v_inv) % ED25519_P
      x = x2.pow((ED25519_P + 3) / 8, ED25519_P)

      # Verify: v * x^2 must equal u or -u mod p
      vx2 = (v * x.pow(2, ED25519_P)) % ED25519_P
      vx2 == u % ED25519_P || vx2 == (ED25519_P - u) % ED25519_P
    end
  end
end
