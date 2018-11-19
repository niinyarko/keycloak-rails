module Keycloak
  module Rails
    class KeycloakException < StandardError; end
    class UserLoginNotFound < KeycloakException; end
    class ProcCookieTokenNotDefined < KeycloakException; end
    class ProcExternalAttributesNotDefined < KeycloakException; end
  end
end