require "keycloak/rails/version"
require "keycloak/rails/exceptions"
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

module Keycloak
  module Rails
    class << self
      attr_accessor :realm, :auth_server_url
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

      def self.get_token_by_client_credentials(client_id = '', secret = '')
        setup_module
  
        client_id = @client_id if client_id.empty?
        secret = @secret if secret.empty?
  
        payload = { 'client_id' => client_id,
                    'client_secret' => secret,
                    'grant_type' => 'client_credentials' }
  
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

      def self.verify_setup
        get_installation if @configuration.nil?
      end

      def self.exec_request(proc_request)
        begin
          proc_request.call
        rescue RestClient::ExceptionWithResponse => err
          raise Rails::KeycloakNetworkException.new(http_code=err.http_code, message=err.message)
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

    module Admin
      class << self
      end

      def self.create_user(user_representation, access_token = nil)
        generic_post("users/", nil, user_representation, access_token)
      end

      def self.update_user(id, user_representation, access_token = nil)
        generic_put("users/#{id}", nil, user_representation, access_token)
      end

      def self.generic_post(service, query_parameters, body_parameter, access_token = nil)
        Keycloak::Rails.generic_request(access_token, full_url(service), query_parameters, body_parameter, 'POST')
      end

      def self.generic_put(service, query_parameters, body_parameter, access_token = nil)
        Keycloak::Rails.generic_request(access_token, full_url(service), query_parameters, body_parameter, 'PUT')
      end

      private

      def self.base_url
        Keycloak::Rails::Client.auth_server_url + "/admin/realms/#{Keycloak::Rails::Client.realm}/"
      end

      def self.full_url(service)
        base_url + service
      end
    end

    private

    def self.generic_request(access_token, uri, query_parameters, body_parameter, method)

      Keycloak::Rails::Client.verify_setup
      final_url = uri

      header = {'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => "Bearer #{access_token}"}

      if query_parameters
        parameters = URI.encode_www_form(query_parameters)
        final_url = final_url << '?' << parameters
      end

      case method.upcase
      when 'GET'
        _request = -> do
          RestClient.get(final_url, header){|response, request, result|
            rescue_response(response)
          }
        end
      when 'POST', 'PUT'
        header["Content-Type"] = 'application/json'
        parameters = JSON.generate body_parameter
        _request = -> do
          case method.upcase
          when 'POST'
            RestClient.post(final_url, parameters, header){|response, request, result|
              rescue_response(response)
            }
          else
            RestClient.put(final_url, parameters, header){|response, request, result|
              rescue_response(response)
            }
          end
        end
      when 'DELETE'
        _request = -> do
          if body_parameter
            header["Content-Type"] = 'application/json'
            parameters = JSON.generate body_parameter
            RestClient::Request.execute(method: :delete, url: final_url,
                          payload: parameters, headers: header) { |response, request, result|
              rescue_response(response)
            }
          else
            RestClient.delete(final_url, header) { |response, request, result|
              rescue_response(response)
            }
          end
        end
      else
        raise
      end

      _request.call

    end

    def self.rescue_response(response)
      case response.code
      when 200..399
        if response.body.empty?
          true
        else
          response.body
        end
      when 400..499
        begin
          response.return!
        rescue RestClient::ExceptionWithResponse => err
          raise Keycloak::Rails::KeycloakNetworkException.new(http_code=err.http_code, message=err.message)
        end
      else
        begin
          response.return!
        rescue RestClient::ExceptionWithResponse => err
          raise Keycloak::Rails::KeycloakNetworkException.new(http_code=err.http_code, message=err.message)
        rescue StandardError => e
          raise Keycloak::Rails::KeycloakException.new(e.message)
        end
      end
    end



  end
end
