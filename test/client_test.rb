require_relative "test_helper"

class Solana::ClientTest < Minitest::Test
  # The previous implementation used `@uri.path` to build the Net::HTTP
  # request, which silently dropped any query string. RPC providers that
  # carry their API key on the query — Helius, QuickNode, Triton — would
  # then receive an authless request and reject it with the upstream's
  # equivalent of "missing api key".
  def test_http_post_preserves_query_string_in_request_path
    client = Solana::Client.new(rpc_url: "https://devnet.helius-rpc.com/?api-key=test-key-123")

    # Capture the Net::HTTP::Post that http_post hands to http.request,
    # without actually opening a connection.
    captured_request = nil
    fake_http = Object.new
    fake_http.define_singleton_method(:use_ssl=) { |_| }
    fake_http.define_singleton_method(:verify_mode=) { |_| }
    fake_http.define_singleton_method(:min_version=) { |_| }
    fake_http.define_singleton_method(:open_timeout=) { |_| }
    fake_http.define_singleton_method(:read_timeout=) { |_| }
    fake_http.define_singleton_method(:request) do |req|
      captured_request = req
      fake_response = Object.new
      fake_response.define_singleton_method(:body) { "{}" }
      fake_response
    end

    Net::HTTP.stub :new, fake_http do
      client.send(:http_post, { jsonrpc: "2.0", id: 1, method: "getHealth", params: [] })
    end

    refute_nil captured_request, "expected http_post to construct a request"
    # Net::HTTPGenericRequest#path returns the full request-URI string
    # (path + "?" + query), so the query must survive into the request.
    assert_equal "/?api-key=test-key-123", captured_request.path
  end

  def test_http_post_uses_root_path_when_url_has_no_path_or_query
    client = Solana::Client.new(rpc_url: "https://api.devnet.solana.com")

    captured_request = nil
    fake_http = Object.new
    fake_http.define_singleton_method(:use_ssl=) { |_| }
    fake_http.define_singleton_method(:verify_mode=) { |_| }
    fake_http.define_singleton_method(:min_version=) { |_| }
    fake_http.define_singleton_method(:open_timeout=) { |_| }
    fake_http.define_singleton_method(:read_timeout=) { |_| }
    fake_http.define_singleton_method(:request) do |req|
      captured_request = req
      fake_response = Object.new
      fake_response.define_singleton_method(:body) { "{}" }
      fake_response
    end

    Net::HTTP.stub :new, fake_http do
      client.send(:http_post, { jsonrpc: "2.0", id: 1, method: "getHealth", params: [] })
    end

    refute_nil captured_request
    assert_equal "/", captured_request.path
  end

  def test_simulate_transaction_sends_correct_rpc_and_returns_value
    client = Solana::Client.new(rpc_url: "https://api.devnet.solana.com")

    captured_body = nil
    client.define_singleton_method(:http_post) do |body|
      captured_body = body
      resp = Object.new
      resp.define_singleton_method(:body) do
        '{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},' \
          '"value":{"err":null,"logs":["Program log: ok"],"unitsConsumed":4200}}}'
      end
      resp
    end

    value = client.simulate_transaction("BASE64TX", sig_verify: false)

    assert_equal "simulateTransaction", captured_body[:method]
    assert_equal "BASE64TX", captured_body[:params][0]
    assert_equal false, captured_body[:params][1][:sigVerify]
    assert_equal "base64", captured_body[:params][1][:encoding]
    assert_nil value["err"]
    assert_equal 4200, value["unitsConsumed"]
    assert_includes value["logs"], "Program log: ok"
  end

  def test_simulate_transaction_surfaces_program_error
    client = Solana::Client.new(rpc_url: "https://api.devnet.solana.com")
    client.define_singleton_method(:http_post) do |_body|
      resp = Object.new
      resp.define_singleton_method(:body) do
        '{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},' \
          '"value":{"err":{"InstructionError":[2,{"Custom":6001}]},"logs":[]}}}'
      end
      resp
    end

    value = client.simulate_transaction("BASE64TX")
    refute_nil value["err"]
  end
end
