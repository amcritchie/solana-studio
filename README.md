# SolanaStudio

Ruby primitives for building on Solana — JSON-RPC client, Ed25519 keypairs, Borsh serialization, and transaction builder with PDA derivation.

> **Part of the McRitchie ecosystem** — see [`ECOSYSTEM.md`](https://github.com/amcritchie/mcritchie-studio/blob/main/docs/ECOSYSTEM.md) for the 5-repo map; [`house-burn-down.md`](https://github.com/amcritchie/mcritchie-studio/blob/main/docs/agents/system/house-burn-down.md) for fresh-Mac recovery.

## Installation

```ruby
# Gemfile
gem "solana-studio", git: "https://github.com/amcritchie/solana-studio.git"
```

## Usage

### Keypair

```ruby
require "solana-studio"

# Generate a new keypair
kp = Solana::Keypair.generate
kp.address          # => "9Fy8P3DvKBh3awt1wr27g4CDh47oDqmJR2FAAQ1bc69D"
kp.to_bytes         # => 64-byte Solana format

# Load from file or env
kp = Solana::Keypair.from_json_file("~/.config/solana/id.json")
kp = Solana::Keypair.from_base58(ENV["SOLANA_ADMIN_KEY"])

# Sign a message
signature = kp.sign("hello".b)
```

### Client (JSON-RPC)

```ruby
client = Solana::Client.new(rpc_url: "https://api.devnet.solana.com")

client.get_balance("9Fy8P3DvKBh3awt...")
client.get_latest_blockhash
client.request_airdrop("9Fy8P3DvKBh3awt...", 1_000_000_000)
client.send_and_confirm(signed_tx_base64)
```

### Borsh Serialization

```ruby
data = Solana::Borsh.encode_u64(1_000_000) +
       Solana::Borsh.encode_string("hello") +
       Solana::Borsh.encode_pubkey(kp.public_key_bytes)
```

### Transaction Builder

```ruby
tx = Solana::Transaction.new
tx.set_recent_blockhash(client.get_latest_blockhash)
tx.add_signer(keypair)
tx.add_instruction(
  program_id: "YourProgramId...",
  accounts: [
    { pubkey: keypair.public_key_bytes, is_signer: true, is_writable: true },
    { pubkey: pda, is_signer: false, is_writable: true }
  ],
  data: Solana::Transaction.anchor_discriminator("your_instruction") + payload
)

signature = client.send_and_confirm(tx.serialize_base64)
```

### PDA Derivation

```ruby
pda, bump = Solana::Transaction.find_pda(
  ["vault".b, wallet_pubkey_bytes],
  program_id_bytes
)
```

## Dependencies

- `ed25519` (~> 1.3) — Ed25519 signing
- Ruby stdlib only (net/http, json, digest, securerandom)

## Development Notes

See [CLAUDE.md](./CLAUDE.md) for detailed development context including the full API reference, design decisions, and AI agent instructions.

## License

MIT
