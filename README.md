# omniauth-bazaruto
Bazaruto OAuth2 Strategy for OmniAuth

## Installation

Use the canonical GitHub repository and a reviewed, full commit ID in the
application's Gemfile. Commit its matching `Gemfile.lock`:

```ruby
gem 'omniauth-bazaruto', github: 'Bazaruto/omniauth-bazaruto', ref: '<reviewed-full-commit-id>'
```

Resolve updates with `bundle update omniauth-bazaruto` after changing the ref.
Review the source diff and transitive lock changes, run the application's SSO
and authorisation tests, and publish the change for review. A SHA prevents a
branch or tag from silently moving; it does not prove the source is trustworthy
or free of vulnerabilities. Never use an unreviewed fork or pull-request ref.
HTTPS and GitHub SSH are supported; never put credentials in the source URL.
Registry gem checksums can be added with `bundle lock --add-checksums`; Bundler
does not provide registry checksums for Git sources. Validate provenance and
the reviewed commit separately. Build applications with Bundler deployment or
frozen mode so builds cannot silently re-resolve their locks.

This gem's development lock is separate from each consuming application's
lock. Its Dependabot configuration proposes weekly gem and action updates;
consumer maintainers must also review updates to this Git ref and upstream
security fixes. Re-run compatibility tests before accepting either update.

## Usage

```ruby
config.omniauth :bazaruto, ENV.fetch('BAZARUTO_APP_ID'), ENV.fetch('BAZARUTO_APP_SECRET'),
  full_host: 'https://consumer.example',
  client_options: { site: 'https://identity.example' }
```

Set `full_host` to the consumer's trusted public origin, independent of request
headers. Alternatively configure `OmniAuth.config.allowed_hosts` with exact
trusted consumer hosts. Register the exact HTTPS callback URI with the provider
and preserve trusted proxy/host validation. The library cannot infer an
application's public hostname or verify a deployed provider registration.
Authentication fails closed when neither a trusted `full_host` nor an explicit
`allowed_hosts` list is configured. Fixed origins must use HTTPS, with only
the explicit local-loopback development exception described below.
Hostname-only allowlists accept default ports only; use a fixed `full_host`
when the approved callback origin has a non-default port.

Use a POST sign-in form and `omniauth-rails_csrf_protection` for Rails. Keep
OmniAuth's request validation and OAuth state checks enabled; never add GET to
`allowed_request_methods` or set `provider_ignores_state`. PKCE with S256 is on
by default, including for confidential clients. The provider must support it.
Authorise and token exchange use the same stored callback URI. OAuth2 2.1+
rejects cross-origin redirects; do not opt back into following them. The
strategy rejects cross-origin endpoint configuration and disabled TLS
verification. HTTP is accepted only for literal loopback hosts with explicit
`allow_insecure_localhost: true` for local development.

`/api/me` must return a JSON object with nonblank string `id`, `email`,
`organisation_id` and `role`. IDs are the provider's opaque stable strings.
Optional names and telephone fields retain their existing mapping. Consumers
must authorise permitted roles and organisations themselves; a successful OAuth
exchange alone does not grant application access. This is OAuth identity from a
configured provider, not OIDC ID-token or issuer-claim validation. Scope is left
to the consumer/provider contract; review provider defaults before rollout.

Use encrypted, HttpOnly, Secure session cookies and an appropriate SameSite
policy. SameSite=Lax normally permits the top-level GET callback; cross-site
POST callbacks need a separately reviewed cookie policy. Keep the state and
PKCE verifier in the session and let the upstream strategy consume them. Do not
store the entire auth hash, access tokens or client secrets in session cookies,
logs or error reports. Authenticate the resulting user through the application's
session framework and preserve its session-renewal behaviour.

Version 0.2 requires Ruby 3.0+, OmniAuth 2.3.1+, omniauth-oauth2 1.10+,
OAuth2 2.1+ and Faraday >= 2.14.3, < 3. The Faraday floor supplies the TLS
hostname-verification API and includes upstream security fixes; the Ruby floor
matches that Faraday release.
This raises the previous dependency floors, adds PKCE and rejects incomplete
identity responses and insecure transport configuration. Test each consumer's
role/account-linking and callback behaviour before adopting its new Git ref.
Existing consumer locks do not change merely because this repository changes.

## Development

Install the development bundle, then run:

```sh
bundle exec ruby -Ilib test/strategy_test.rb
```

All HTTP is stubbed and real network connections are disabled by the tests.
The CI matrix resolves against Rack 2.2 and 3.2 on Ruby 3.4 and 4.0, using
both Faraday 2.14.3 and the latest compatible Faraday 2.x. Ruby 3.0 is the
dependency metadata floor; this matrix does not verify every older Ruby minor.
To exercise a Rack series locally, set `RACK_VERSION='~> 2.2'` (or `~> 3.2`), run
`bundle lock --update`, install and run the tests. Restore the normal lock
afterwards. Set `FARADAY_VERSION=2.14.3` to exercise the Faraday floor.
The lock records the normal development bundle, not every supported
Ruby/Rack combination. Build a package with `gem build omniauth-bazaruto.gemspec`;
publishing packages or tags is a separate maintainer action.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
