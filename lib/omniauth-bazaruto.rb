require "omniauth-bazaruto/version"
require 'omniauth-oauth2'
require 'uri'
require 'ipaddr'

module OmniAuth
  module Strategies
    class Bazaruto < OmniAuth::Strategies::OAuth2
      option :name, :bazaruto
      option :pkce, true
      option :allow_insecure_localhost, false

      option :client_options, {
          :site => "https://app.bazaruto.com",
          :authorize_url => "/oauth/authorize",
          :token_url => "/oauth/token"
      }

      uid { raw_info["id"] }

      info do
        {
            email: raw_info["email"],
            first_name: raw_info["first_name"],
            last_name: raw_info["last_name"],
            organisation_id: raw_info["organisation_id"],
            telephone: raw_info["telephone"],
            cellphone: raw_info["cellphone"],
            role: raw_info["role"]
        }
      end

      def raw_info
        @raw_info ||= begin
          profile = access_token.get('/api/me').parsed
          unless profile.is_a?(Hash) && %w[id email organisation_id role].all? { |key| nonempty_string?(profile[key]) }
            raise CallbackError.new(:invalid_profile, "Bazaruto returned an invalid identity profile")
          end
          profile
        end
      end

      def client
        validate_client_options!
        super
      end

      def full_host
        origin = super
        uri = URI.parse(origin.to_s)
        secure = uri.scheme == 'https' || (options.allow_insecure_localhost && uri.scheme == 'http' && loopback?(uri.hostname))
        unless secure && uri.host && !uri.userinfo && !uri.query && !uri.fragment && ['', '/'].include?(uri.path)
          raise CallbackError.new(:invalid_configuration, "Bazaruto requires a trusted consumer origin")
        end
        origin.sub(%r{/$}, '')
      rescue URI::Error
        raise CallbackError.new(:invalid_configuration, "Bazaruto requires a valid consumer origin")
      end

      protected

      def allowed_host?
        (full_host_set? || !OmniAuth.config.allowed_hosts.nil?) && super
      end

      private

      def nonempty_string?(value)
        value.is_a?(String) && !value.strip.empty?
      end

      def validate_client_options!
        config = options.client_options
        site = URI.parse(config[:site].to_s)
        secure = site.scheme == 'https' || (options.allow_insecure_localhost && site.scheme == 'http' && loopback?(site.hostname))
        valid_site = secure && site.host && !site.userinfo && !site.query && !site.fragment
        valid_endpoints = [:authorize_url, :token_url].all? do |key|
          endpoint = URI.join(site.to_s, config[key].to_s)
          [endpoint.scheme, endpoint.host, endpoint.port] == [site.scheme, site.host, site.port] && !endpoint.userinfo && !endpoint.fragment
        end
        ssl_settings = [config[:ssl], config.dig(:connection_opts, :ssl)].compact
        insecure_tls = ssl_settings.any? do |ssl|
          ssl[:verify] == false || ssl[:verify_hostname] == false || ssl[:verify_mode] == 0
        end
        if !valid_site || !valid_endpoints || insecure_tls || config[:allow_cross_origin_redirects]
          raise CallbackError.new(:invalid_configuration, "Bazaruto requires verified TLS and same-origin OAuth endpoints")
        end
      rescue URI::Error
        raise CallbackError.new(:invalid_configuration, "Bazaruto requires valid OAuth endpoint URLs")
      end

      def loopback?(host)
        host == 'localhost' || IPAddr.new(host.to_s).loopback?
      rescue IPAddr::Error
        false
      end
    end
  end
end
