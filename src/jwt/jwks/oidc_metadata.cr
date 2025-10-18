module JWT
  class JWKS
    # OIDC metadata structure from /.well-known/openid-configuration
    struct OIDCMetadata
      include JSON::Serializable

      property issuer : String
      property jwks_uri : String
      property authorization_endpoint : String?
      property token_endpoint : String?
      property userinfo_endpoint : String?
      property end_session_endpoint : String?

      @[JSON::Field(key: "response_types_supported")]
      property response_types_supported : Array(String)?

      @[JSON::Field(key: "subject_types_supported")]
      property subject_types_supported : Array(String)?

      @[JSON::Field(key: "id_token_signing_alg_values_supported")]
      property id_token_signing_alg_values_supported : Array(String)?
    end
  end
end
