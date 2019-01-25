require "omniauth/bazaruto/version"
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Bazaruto < OmniAuth::Strategies::OAuth2
      # change the class name and the :name option to match your application name
      option :name, :bazaruto

      option :client_options, {
          :site => "https://app.bazaruto.com",
          :authorize_url => "/oauth/authorize"
      }

      uid { raw_info["id"] }

      info do
        {
            email: raw_info["email"],
            organisation_id: raw_info["organisation_id"],
            telephone: raw_info["telephone"],
            cellphone: raw_info["cellphone"],
            role: raw_info["role"]
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/api/me').parsed
      end
    end
  end
end
