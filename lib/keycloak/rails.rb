require "keycloak/rails/version"
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

module Keycloak
  module Rails
    class << self
      attr_accessor :proxy, :generate_request_exception, :keycloak_controller,
                    :proc_cookie_token, :proc_external_attributes,
                    :realm, :auth_server_url
    end

    module Client
      class << self
        attr_accessor :realm, :auth_server_url
        attr_reader :client_id, :secret, :configuration, :public_key
      end

      KEYCLOAK_JSON_FILE = 'keycloak.json'

      def self.get_token(user, password)
        setup_module

        payload = { 'client_id' => @client_id,
                    'client_secret' => @secret,
                    'username' => user,
                    'password' => password,
                    'grant_type' => 'password' }

        mount_request_token(payload)
      end

      private

      def self.get_installation
        if File.exists?(KEYCLOAK_JSON_FILE)
          installation = JSON File.read(KEYCLOAK_JSON_FILE)
          @realm = installation["realm"]
          @client_id = installation["resource"]
          @secret = installation["credentials"]["secret"]
          @auth_server_url = installation["auth-server-url"]
          openid_configuration
        else
          raise "#{KEYCLOAK_JSON_FILE} and relm settings not found."
        end
      end

      def self.setup_module
        get_installation
      end

      def self.exec_request(proc_request)
        begin
          proc_request.call
        rescue RestClient::ExceptionWithResponse => err
          raise Keycloak::Rails::KeycloakException.new err
        end
      end

      def self.openid_configuration
        config_url = "#{@auth_server_url}/realms/#{@realm}/.well-known/openid-configuration"
        _request = -> do
          RestClient.get config_url
        end
        response = exec_request _request
        if response.code == 200
          @configuration = JSON response.body
        else
          response.return!
        end
      end

      def self.mount_request_token(payload)
        header = {'Content-Type' => 'application/x-www-form-urlencoded'}

        _request = -> do
          RestClient.post(@configuration['token_endpoint'], payload, header){|response, request, result|
            case response.code
            when 200
              response.body
            else
              response.return!
            end
          }
        end

        exec_request _request
      end

     end
  end
end
