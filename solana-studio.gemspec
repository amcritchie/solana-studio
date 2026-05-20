Gem::Specification.new do |spec|
  spec.name          = "solana-studio"
  spec.version       = "0.4.2"
  spec.authors       = ["Alex McRitchie"]
  spec.email         = ["solana-studio@mcritchie.studio"]

  spec.summary       = "Ruby primitives for Solana: JSON-RPC client, Ed25519 keypairs, Borsh serialization, transaction builder, wallet signature verifier"
  spec.description   = "A lightweight Ruby gem providing generic Solana building blocks — JSON-RPC client with retry, Ed25519 keypair management, Borsh encoding/decoding, transaction builder with PDA derivation and Anchor discriminators, SPL Token instruction helpers, and a pure-Ruby wallet-signature verifier (Solana::AuthVerifier)."
  spec.homepage      = "https://github.com/amcritchie/solana-studio"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata = {
    "homepage_uri"    => "https://github.com/amcritchie/solana-studio",
    "source_code_uri" => "https://github.com/amcritchie/solana-studio",
    "bug_tracker_uri" => "https://github.com/amcritchie/solana-studio/issues",
    "changelog_uri"   => "https://github.com/amcritchie/solana-studio/blob/main/CHANGELOG.md"
  }

  spec.files         = Dir["lib/**/*.rb", "README.md", "LICENSE", "CHANGELOG.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "ed25519", "~> 1.3"
end
