require "net/http"
require "json"
require "uri"
require "openssl"

module Solana
  class Client
    class RpcError < StandardError
      attr_reader :code
      def initialize(message, code: nil)
        @code = code
        super(message)
      end
    end

    class InsecureRpcUrlError < ArgumentError; end

    MAX_RETRIES = 3
    RETRY_DELAY = 1 # seconds

    DEFAULT_RPC_URL = "https://api.devnet.solana.com"

    # Hostnames where plain http:// is permitted (local testing only).
    HTTP_OK_HOSTS = %w[localhost 127.0.0.1 ::1 0.0.0.0].freeze

    def initialize(rpc_url: nil)
      @rpc_url = rpc_url || ENV.fetch("SOLANA_RPC_URL", DEFAULT_RPC_URL)
      @uri = URI.parse(@rpc_url)
      validate_rpc_scheme!
      @request_id = 0
    end

    def get_account_info(pubkey, encoding: "base64", commitment: nil)
      config = { encoding: encoding }
      config[:commitment] = commitment if commitment
      call("getAccountInfo", [pubkey, config])
    end

    def get_token_account_balance(pubkey)
      call("getTokenAccountBalance", [pubkey])
    end

    def get_latest_blockhash(commitment: "finalized")
      result = call("getLatestBlockhash", [{ commitment: commitment }])
      result.dig("value", "blockhash")
    end

    def get_minimum_balance_for_rent_exemption(size)
      call("getMinimumBalanceForRentExemption", [size])
    end

    def send_transaction(signed_tx_base64, skip_preflight: false)
      opts = { encoding: "base64", skipPreflight: skip_preflight }
      call("sendTransaction", [signed_tx_base64, opts])
    end

    def confirm_transaction(signature, commitment: "confirmed")
      call("getSignatureStatuses", [[signature], { searchTransactionHistory: true }])
    end

    def send_and_confirm(signed_tx_base64, timeout: 30, skip_preflight: false)
      signature = send_transaction(signed_tx_base64, skip_preflight: skip_preflight)

      deadline = Time.now + timeout
      loop do
        sleep 1
        result = confirm_transaction(signature)
        status = result.dig("value", 0)

        if status
          if status["err"]
            raise RpcError.new("Transaction failed: #{status['err']}")
          end
          return signature if status["confirmationStatus"] == "confirmed" || status["confirmationStatus"] == "finalized"
        end

        raise RpcError.new("Transaction confirmation timeout") if Time.now > deadline
      end
    end

    def request_airdrop(pubkey, lamports)
      call("requestAirdrop", [pubkey, lamports])
    end

    def get_balance(pubkey)
      call("getBalance", [pubkey])
    end

    def get_transaction(signature, commitment: "confirmed")
      call("getTransaction", [signature, { encoding: "json", commitment: commitment }])
    end

    def get_token_accounts_by_owner(owner_pubkey)
      call("getTokenAccountsByOwner", [
        owner_pubkey,
        { programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
        { encoding: "jsonParsed" }
      ])
    end

    private

    def call(method, params = [])
      @request_id += 1
      body = {
        jsonrpc: "2.0",
        id: @request_id,
        method: method,
        params: params
      }

      retries = 0
      begin
        response = http_post(body)
        parsed = JSON.parse(response.body)

        if parsed["error"]
          error = parsed["error"]
          raise RpcError.new(error["message"], code: error["code"])
        end

        parsed["result"]
      rescue RpcError => e
        # Retry on rate limit (429) or blockhash expiry
        if retries < MAX_RETRIES && retryable_error?(e)
          retries += 1
          sleep RETRY_DELAY * retries
          retry
        end
        raise
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNRESET => e
        if retries < MAX_RETRIES
          retries += 1
          sleep RETRY_DELAY * retries
          retry
        end
        raise RpcError.new("Network error: #{e.message}")
      end
    end

    def http_post(body)
      http = Net::HTTP.new(@uri.host, @uri.port)
      if @uri.scheme == "https"
        http.use_ssl = true
        # Belt-and-suspenders: Net::HTTP defaults to VERIFY_PEER in modern Ruby
        # but a) some older builds have shipped with weaker defaults and b)
        # being explicit here protects against future regressions or downstream
        # monkey-patches.
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.min_version = OpenSSL::SSL::TLS1_2_VERSION
      end
      http.open_timeout = 10
      http.read_timeout = 30

      # `request_uri` preserves the query string (path + "?" + query).
      # `path` alone drops it, which silently breaks RPC providers that
      # carry credentials on the query — e.g. Helius:
      # `https://devnet.helius-rpc.com/?api-key=…`. The server replies
      # with `{"error":"missing api key"}` and the client retries.
      request_path = @uri.request_uri
      request = Net::HTTP::Post.new(request_path.empty? ? "/" : request_path)
      request["Content-Type"] = "application/json"
      request.body = body.to_json

      http.request(request)
    end

    def retryable_error?(error)
      return true if error.code == 429 # rate limited
      return true if error.message.include?("Blockhash not found")
      false
    end

    # Reject plain http:// RPC URLs unless the host is local. Prevents
    # accidental cleartext communication with public RPC providers.
    def validate_rpc_scheme!
      return if @uri.scheme == "https"
      if @uri.scheme == "http" && HTTP_OK_HOSTS.include?(@uri.host.to_s.downcase)
        return
      end
      raise InsecureRpcUrlError,
            "Solana::Client requires an https:// RPC URL (got #{@rpc_url.inspect}). " \
            "Plain http:// is only allowed for localhost. Set SOLANA_RPC_URL to a " \
            "TLS endpoint (e.g. https://api.mainnet-beta.solana.com or your " \
            "paid provider's HTTPS endpoint)."
    end
  end
end
