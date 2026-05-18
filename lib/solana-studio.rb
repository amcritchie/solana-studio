# Entry point for the `solana-studio` gem. The actual code lives in
# `lib/solana_studio.rb` (which exports the `SolanaStudio` module + the
# `Solana::*` namespace). This shim exists so `gem "solana-studio"` in
# a Gemfile loads correctly without consumers needing to add
# `require: "solana_studio"`.
require_relative "solana_studio"
