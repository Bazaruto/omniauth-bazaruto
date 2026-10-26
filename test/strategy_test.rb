require 'minitest/autorun'
require 'webmock/minitest'
require 'rack/mock'
require 'json'
require 'stringio'
require 'omniauth-bazaruto'

WebMock.disable_net_connect!

class StrategyTest < Minitest::Test
  PROVIDER = 'https://identity.example'.freeze
  CALLBACK = 'https://client.example/auth/bazaruto/callback'.freeze
  PROFILE = {
    'id' => 'synthetic-user', 'email' => 'person@example.test',
    'first_name' => 'Example', 'last_name' => 'Person',
    'organisation_id' => 'synthetic-organisation', 'role' => 'example-role'
  }.freeze

  def setup
    WebMock.reset!
    @original_config = OmniAuth::Configuration.defaults.keys.to_h { |key| [key, OmniAuth.config.public_send(key)] }
    OmniAuth.config.test_mode = false
    OmniAuth.config.logger = Logger.new(File::NULL)
    OmniAuth.config.allowed_hosts = ['client.example']
    OmniAuth.config.on_failure = lambda do |env|
      [401, {'content-type' => 'text/plain'}, [env['omniauth.error.type'].to_s]]
    end
    @session = {}
    @app = lambda do |env|
      @auth = env['omniauth.auth']
      [200, {'content-type' => 'text/plain'}, ['application']]
    end
    @strategy = strategy
  end

  def teardown
    @original_config.each { |key, value| OmniAuth.config.public_send("#{key}=", value) }
  end

  def strategy(**options)
    OmniAuth::Strategies::Bazaruto.new(@app, 'synthetic-client', 'synthetic-secret',
      **{client_options: {site: PROVIDER}}.merge(options))
  end

  def request(path, method: 'GET', params: {}, session: @session, headers: {})
    env = Rack::MockRequest.env_for("https://client.example#{path}",
      method: method, params: params)
    @strategy.call(env.merge('rack.session' => session).merge(headers))
  end

  def start_sign_in
    token = Rack::Protection::AuthenticityToken.token(@session)
    status, headers, = request('/auth/bazaruto', method: 'POST', params: {authenticity_token: token})
    assert_equal 302, status
    URI.decode_www_form(URI(headers['location']).query).to_h
  end

  def callback(state, **params)
    request('/auth/bazaruto/callback', params: {state: state, code: 'synthetic-code'}.merge(params))
  end

  def stub_success(profile = PROFILE)
    @token_request = stub_request(:post, "#{PROVIDER}/oauth/token")
      .to_return(status: 200, headers: {'content-type' => 'application/json'},
        body: JSON.generate(access_token: 'synthetic-access-token', token_type: 'Bearer'))
    @profile_request = stub_request(:get, "#{PROVIDER}/api/me")
      .with(headers: {'Authorization' => 'Bearer synthetic-access-token'})
      .to_return(status: 200, headers: {'content-type' => 'application/json'}, body: JSON.generate(profile))
  end

  def test_post_requires_a_valid_authenticity_token
    assert_equal 200, request('/auth/bazaruto')[0]
    assert_equal 'authenticity_error', request('/auth/bazaruto', method: 'POST')[2].join
    assert_nil @session['omniauth.state']
  end

  def test_authorisation_code_pkce_and_identity_contract
    stub_success
    auth_params = start_sign_in
    assert_equal CALLBACK, auth_params['redirect_uri']
    assert_equal 'S256', auth_params['code_challenge_method']
    assert_equal 48, auth_params.fetch('state').size
    @token_request.with do |req|
      body = URI.decode_www_form(req.body).to_h
      verifier = body.fetch('code_verifier')
      assert_equal auth_params['code_challenge'], Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
      assert_equal CALLBACK, body['redirect_uri']
      assert_equal 'authorization_code', body['grant_type']
      assert_equal 'synthetic-code', body['code']
      refute_includes body['redirect_uri'], 'state='
      true
    end
    assert_equal 200, callback(auth_params['state'])[0]
    assert_equal 'synthetic-user', @auth.uid
    assert_equal 'bazaruto', @auth.provider.to_s
    assert_equal PROFILE['organisation_id'], @auth.info.organisation_id
    assert_equal PROFILE['role'], @auth.info.role
    assert_equal PROFILE['first_name'], @auth.info.first_name
    assert_requested @token_request, times: 1
    assert_requested @profile_request, times: 1
    refute_includes @session.values.inspect, 'synthetic-access-token'
    assert_nil @session['omniauth.pkce.verifier']
  end

  def test_missing_mismatched_and_structured_state_never_exchange_a_code
    stub_success
    [nil, '', 'wrong-state', {'nested' => 'state'}].each do |state|
      start_sign_in
      assert_equal 'csrf_detected', callback(state)[2].join
      assert_nil @auth
    end
    assert_not_requested @token_request
    assert_not_requested @profile_request
  end

  def test_state_is_single_use
    stub_success
    state = start_sign_in.fetch('state')
    assert_equal 200, callback(state)[0]
    assert_equal 'csrf_detected', callback(state)[2].join
    assert_requested @token_request, times: 1
  end

  def test_denial_requires_state_and_does_not_exchange_a_code
    stub_success
    start_sign_in
    assert_equal 'csrf_detected', callback('wrong-state', error: 'access_denied')[2].join
    state = start_sign_in.fetch('state')
    assert_equal 'access_denied', callback(state, error: 'access_denied')[2].join
    assert_not_requested @token_request
  end

  def test_two_sign_ins_keep_their_own_redirect_and_pkce_verifier
    stub_success
    first = start_sign_in
    second = start_sign_in
    refute_equal first['state'], second['state']
    refute_equal first['code_challenge'], second['code_challenge']
    assert_equal 200, callback(first['state'])[0]
    assert_equal 200, callback(second['state'])[0]
    assert_requested @token_request, times: 2
  end

  def test_forged_callback_host_is_rejected_before_network_access
    stub_success
    state = start_sign_in.fetch('state')
    response = request('/auth/bazaruto/callback', params: {state: state, code: 'synthetic-code'},
      headers: {'HTTP_HOST' => 'untrusted.example'})
    assert_equal 'invalid_host', response[2].join
    assert_not_requested @token_request
  end

  def test_missing_trusted_consumer_configuration_fails_closed
    OmniAuth.config.allowed_hosts = nil
    stub_success
    token = Rack::Protection::AuthenticityToken.token(@session)
    response = request('/auth/bazaruto', method: 'POST', params: {authenticity_token: token})
    assert_equal 'invalid_host', response[2].join
    assert_not_requested @token_request
  end

  def test_fixed_consumer_origin_ignores_forged_request_headers
    OmniAuth.config.allowed_hosts = nil
    @strategy = strategy(full_host: 'https://consumer.example/')
    token = Rack::Protection::AuthenticityToken.token(@session)
    response = request('/auth/bazaruto', method: 'POST', params: {authenticity_token: token},
      headers: {'HTTP_HOST' => 'untrusted.example', 'HTTP_X_FORWARDED_HOST' => 'untrusted.example'})
    params = URI.decode_www_form(URI(response[1]['location']).query).to_h
    assert_equal 'https://consumer.example/auth/bazaruto/callback', params['redirect_uri']
  end

  def test_fixed_consumer_origin_requires_https_or_explicit_http_loopback
    ['http://consumer.example', 'https://user:password@consumer.example',
      'https://consumer.example/path', 'https://consumer.example?query=1', 'https://consumer.example#fragment'].each do |origin|
      assert_raises(OmniAuth::Strategies::OAuth2::CallbackError) { strategy(full_host: origin).full_host }
    end
    local = strategy(full_host: 'http://localhost:3001/', allow_insecure_localhost: true)
    assert_equal 'http://localhost:3001', local.full_host
  end

  def test_hostname_allowlist_does_not_trust_a_forged_callback_port
    token = Rack::Protection::AuthenticityToken.token(@session)
    response = request('/auth/bazaruto', method: 'POST', params: {authenticity_token: token},
      headers: {'HTTP_HOST' => 'client.example:4443', 'HTTP_X_FORWARDED_HOST' => 'client.example:4443'})
    assert_equal 401, response[0]
    assert_nil @auth
    fixed = strategy(full_host: 'https://consumer.example:4443')
    assert_equal 'https://consumer.example:4443', fixed.full_host
  end

  def test_global_faraday_defaults_cannot_disable_oauth_tls_verification
    previous = Faraday.default_connection_options
    Faraday.default_connection_options = {ssl: {verify: false, verify_hostname: false, verify_mode: 0}}
    connection = strategy.client.connection
    assert_equal true, connection.ssl.verify
    assert_equal true, connection.ssl.verify_hostname
    assert_equal OpenSSL::SSL::VERIFY_PEER, connection.ssl.verify_mode
    assert_equal false, Faraday.default_connection_options.ssl.verify
  ensure
    Faraday.default_connection_options = previous
  end

  def test_callback_port_is_checked_even_with_a_stored_redirect_uri
    stub_success
    state = start_sign_in.fetch('state')
    response = request('/auth/bazaruto/callback', params: {state: state, code: 'synthetic-code'},
      headers: {'HTTP_HOST' => 'client.example:4443'})
    assert_equal 401, response[0]
    assert_not_requested @token_request
  end

  def test_dynamic_trusted_origin_is_validated_again_at_callback
    stub_success
    selector = lambda do |env|
      raise OmniAuth::Error, 'invalid_consumer_origin' unless Rack::Request.new(env).host == 'client.example'

      'https://client.example'
    end
    @strategy = strategy(full_host: selector)
    state = start_sign_in.fetch('state')
    response = request('/auth/bazaruto/callback', params: {state: state, code: 'synthetic-code'},
      headers: {'HTTP_HOST' => 'untrusted.example'})
    assert_equal 401, response[0]
    assert_not_requested @token_request
  end

  def test_invalid_profile_cannot_reach_the_application
    [nil, [], {}, PROFILE.merge('id' => nil), PROFILE.merge('id' => ''),
      PROFILE.merge('id' => []), PROFILE.merge('organisation_id' => ' '),
      PROFILE.merge('email' => {}), PROFILE.merge('role' => nil)].each do |profile|
      WebMock.reset!
      @auth = nil
      stub_success(profile)
      response = callback(start_sign_in.fetch('state'))
      assert_equal 401, response[0]
      assert_equal 'invalid_credentials', response[2].join
      assert_nil @auth
    end
  end

  def test_token_and_profile_cross_origin_redirects_are_rejected
    [:token, :profile].each do |endpoint|
      WebMock.reset!
      @auth = nil
      stub_success
      location = 'https://untrusted.example/redirect'
      verb, path = endpoint == :token ? [:post, '/oauth/token'] : [:get, '/api/me']
      stub_request(verb, "#{PROVIDER}#{path}").to_return(status: 302, headers: {'location' => location})
      response = callback(start_sign_in.fetch('state'))
      assert_equal 401, response[0]
      assert_nil @auth
      assert_not_requested(:any, %r{https://untrusted\.example/})
    end
  end

  def test_profile_failures_never_authenticate
    [401, 500].each do |status|
      WebMock.reset!
      stub_success
      stub_request(:get, "#{PROVIDER}/api/me").to_return(status: status)
      assert_equal 401, callback(start_sign_in.fetch('state'))[0]
      assert_nil @auth
    end
  end

  def test_token_errors_missing_tokens_and_timeouts_never_authenticate
    [{status: 401}, {status: 200, headers: {'content-type' => 'application/json'}, body: '{}'}].each do |response|
      WebMock.reset!
      stub_success
      stub_request(:post, "#{PROVIDER}/oauth/token").to_return(response)
      assert_equal 401, callback(start_sign_in.fetch('state'))[0]
      assert_nil @auth
      assert_not_requested @profile_request
    end
    WebMock.reset!
    stub_success
    stub_request(:post, "#{PROVIDER}/oauth/token").to_timeout
    assert_equal 'timeout', callback(start_sign_in.fetch('state'))[2].join
    assert_nil @auth
    assert_not_requested @profile_request
  end

  def test_insecure_or_cross_origin_configuration_is_rejected
    [{site: 'http://identity.example'}, {site: 'https://user:password@identity.example'},
      {site: PROVIDER, token_url: 'https://untrusted.example/token'},
      {site: PROVIDER, authorize_url: '//untrusted.example/authorize'},
      {site: PROVIDER, ssl: {verify: false}},
      {site: PROVIDER, ssl: {verify_mode: 0}},
      {site: PROVIDER, ssl: {verify_hostname: false}},
      {site: PROVIDER, connection_opts: {ssl: {verify: false}}},
      {site: PROVIDER, allow_cross_origin_redirects: true}].each do |client_options|
      assert_raises(OmniAuth::Strategies::OAuth2::CallbackError) { strategy(client_options: client_options).client }
    end
  end

  def test_http_loopback_requires_explicit_development_opt_in
    assert_raises(OmniAuth::Strategies::OAuth2::CallbackError) { strategy(client_options: {site: 'http://127.0.0.1:3000'}).client }
    assert_equal 'http://127.0.0.1:3000', strategy(allow_insecure_localhost: true, client_options: {site: 'http://127.0.0.1:3000'}).client.site
    assert_raises(OmniAuth::Strategies::OAuth2::CallbackError) { strategy(allow_insecure_localhost: true, client_options: {site: 'http://identity.example'}).client }
  end
end
