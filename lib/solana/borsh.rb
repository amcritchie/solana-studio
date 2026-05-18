module Solana
  module Borsh
    # Cap on the bytes any single length-prefixed decode (vec, string) can
    # claim. Malicious / corrupt RPC responses can carry a length field of
    # e.g. 4_000_000_000, which without this guard would OOM the process
    # when the caller allocates accordingly. 10MB is more than any sane
    # Solana account / instruction payload — adjust per consumer needs.
    MAX_DECODED_FIELD_BYTES = 10 * 1024 * 1024

    class DecodedFieldTooLarge < StandardError; end

    module_function

    def encode_u8(value)
      [value].pack("C")
    end

    def encode_u16(value)
      [value].pack("v") # little-endian u16
    end

    def encode_u32(value)
      [value].pack("V") # little-endian u32
    end

    def encode_u64(value)
      [value].pack("Q<") # little-endian u64
    end

    def encode_i64(value)
      [value].pack("q<") # little-endian i64
    end

    def encode_pubkey(pubkey_bytes)
      pubkey_bytes = Keypair.decode_base58(pubkey_bytes) if pubkey_bytes.is_a?(String) && pubkey_bytes.length != 32
      pubkey_bytes = pubkey_bytes.b if pubkey_bytes.is_a?(String)
      raise "Pubkey must be 32 bytes, got #{pubkey_bytes.bytesize}" unless pubkey_bytes.bytesize == 32
      pubkey_bytes
    end

    def encode_bytes32(bytes)
      bytes = bytes.b if bytes.is_a?(String)
      raise "Expected 32 bytes, got #{bytes.bytesize}" unless bytes.bytesize == 32
      bytes
    end

    def encode_vec(items, &block)
      encoded_items = items.map { |item| block.call(item) }.join
      encode_u32(items.length) + encoded_items
    end

    def encode_string(str)
      bytes = str.encode("UTF-8").b
      encode_u32(bytes.bytesize) + bytes
    end

    def encode_bool(value)
      encode_u8(value ? 1 : 0)
    end

    # Decode helpers

    def decode_u8(bytes, offset = 0)
      [bytes.byteslice(offset, 1).unpack1("C"), offset + 1]
    end

    def decode_u16(bytes, offset = 0)
      [bytes.byteslice(offset, 2).unpack1("v"), offset + 2]
    end

    def decode_u32(bytes, offset = 0)
      [bytes.byteslice(offset, 4).unpack1("V"), offset + 4]
    end

    def decode_u64(bytes, offset = 0)
      [bytes.byteslice(offset, 8).unpack1("Q<"), offset + 8]
    end

    def decode_pubkey(bytes, offset = 0)
      [bytes.byteslice(offset, 32), offset + 32]
    end

    # Length-prefixed string. Reads u32 length then `length` bytes of UTF-8.
    # Raises DecodedFieldTooLarge if the declared length exceeds the cap —
    # protects callers from allocation-bomb DoS via crafted RPC responses.
    def decode_string(bytes, offset = 0)
      length, offset = decode_u32(bytes, offset)
      check_field_length!(length, "string")
      str = bytes.byteslice(offset, length).to_s.force_encoding("UTF-8")
      [str, offset + length]
    end

    # Length-prefixed array. block is called per element with (bytes, offset)
    # and must return [value, new_offset]. Bounded by MAX_DECODED_FIELD_BYTES
    # on the declared count to prevent allocation-bomb DoS.
    def decode_vec(bytes, offset = 0, &block)
      length, offset = decode_u32(bytes, offset)
      check_field_length!(length, "vec")
      items = []
      length.times do
        item, offset = block.call(bytes, offset)
        items << item
      end
      [items, offset]
    end

    def check_field_length!(length, kind)
      if length > MAX_DECODED_FIELD_BYTES
        raise DecodedFieldTooLarge,
              "Borsh #{kind} declared length #{length} exceeds cap " \
              "(MAX_DECODED_FIELD_BYTES=#{MAX_DECODED_FIELD_BYTES}). " \
              "Likely a corrupt or malicious RPC response."
      end
    end
  end
end
