module Keycloak
  module Rails
    class KeycloakException < StandardError; end
    class KeycloakNetworkException < KeycloakException
      attr_accessor :http_code
      attr_accessor :message

      def initialize(http_code = nil, message = nil)
        @http_code = http_code
        @message = message
      end
    end
  end
end