require "json"
require "http/client"
require "./jwks/*"

module JWT
  # JWKS (JSON Web Key Set) helper for JWT validation with support for OIDC discovery
  #
  # Supports:
  # - Fetching OIDC metadata from /.well-known/openid-configuration
  # - Fetching and caching JWKS keys
  # - Local JWT validation (for service-to-service tokens)
  # - Remote JWT validation via JWKS
  #
  # Example:
  # ```
  # # Initialize with optional local keys
  # jwks = JWT::JWKS.new(
  #   local_keys: {"local_key_id" => "secret"},
  #   local_algorithm: JWT::Algorithm::HS256
  # )
  #
  # # Validate a token and check scopes
  # payload = jwks.validate(token, issuer: "https://example.com", audience: "my-app")
  # if payload
  #   scopes = JWT::JWKS.extract_scopes(payload)
  #   if scopes.includes?("read")
  #     # User has required scope
  #   end
  # end
  # ```
  class JWKS
    # Cached metadata and keys
    private struct CachedData(T)
      property data : T
      property expires_at : Time

      def initialize(@data : T, ttl : Time::Span)
        @expires_at = Time.utc + ttl
      end

      def expired? : Bool
        Time.utc >= @expires_at
      end
    end

    # Default cache TTL (10 minutes)
    DEFAULT_CACHE_TTL = 10.minutes

    # Local keys for service-to-service JWT validation
    getter local_keys : Hash(String, String)?
    getter local_algorithm : Algorithm?

    # Cache TTL
    getter cache_ttl : Time::Span

    # Cached OIDC metadata by issuer
    @metadata_cache = Hash(String, CachedData(OIDCMetadata)).new

    # Cached JWKS by jwks_uri
    @jwks_cache = Hash(String, CachedData(JWKSet)).new

    # Mutex for thread-safe cache access
    @cache_mutex = Mutex.new

    # Initialize JWKS validator
    #
    # @param local_keys Optional hash of kid => key for local JWT validation
    # @param local_algorithm Algorithm to use for local keys
    # @param cache_ttl Cache TTL for OIDC metadata and JWKS (default: 10 minutes)
    def initialize(
      @local_keys : Hash(String, String)? = nil,
      @local_algorithm : Algorithm? = nil,
      @cache_ttl : Time::Span = DEFAULT_CACHE_TTL,
    )
    end

    # Validate a JWT token
    #
    # This method will:
    # 1. Try to validate using local keys if provided
    # 2. Fall back to JWKS validation if not a local token
    #
    # @param token JWT token string
    # @param issuer Expected issuer (for OIDC metadata lookup)
    # @param audience Expected audience(s) for validation
    # @param validate_claims Whether to validate standard claims (exp, nbf, etc.)
    # @return Validated payload or nil if validation fails
    #
    # Example:
    # ```
    # payload = jwks.validate(token, issuer: "https://example.com", audience: "my-app")
    # if payload
    #   # Check scopes
    #   scopes = JWT::JWKS.extract_scopes(payload)
    #   if scopes.includes?("read")
    #     # Token is valid with required scope
    #   end
    # end
    # ```
    def validate(
      token : String,
      issuer : String? = nil,
      audience : String | Array(String)? = nil,
      validate_claims : Bool = true,
    ) : JSON::Any?
      # First, try to decode without verification to inspect the header
      unverified_payload, header = JWT.decode(token, verify: false, validate: false)

      # Try local validation first if local keys are configured
      if local_payload = try_local_validation(token, header, unverified_payload, validate_claims)
        return local_payload
      end

      # Fall back to JWKS validation
      validate_with_jwks(
        token,
        header,
        issuer: issuer,
        audience: audience,
        validate_claims: validate_claims
      )
    rescue e : JWT::DecodeError
      nil
    end

    # Fetch OIDC metadata for an issuer
    #
    # @param issuer Issuer URL (e.g., "https://login.microsoftonline.com/{tenant}/v2.0")
    # @return OIDC metadata
    def fetch_oidc_metadata(issuer : String) : OIDCMetadata
      @cache_mutex.synchronize do
        # Check cache first
        if cached = @metadata_cache[issuer]?
          return cached.data unless cached.expired?
        end

        # Fetch from well-known endpoint
        well_known_url = "#{issuer.rstrip("/")}/.well-known/openid-configuration"
        response = HTTP::Client.get(well_known_url)

        unless response.success?
          raise DecodeError.new("Failed to fetch OIDC metadata from #{well_known_url}: #{response.status}")
        end

        metadata = OIDCMetadata.from_json(response.body)
        @metadata_cache[issuer] = CachedData.new(metadata, @cache_ttl)
        metadata
      end
    end

    # Fetch JWKS from a jwks_uri
    #
    # @param jwks_uri JWKS URI
    # @return JWKS key set
    def fetch_jwks(jwks_uri : String) : JWKSet
      @cache_mutex.synchronize do
        # Check cache first
        if cached = @jwks_cache[jwks_uri]?
          return cached.data unless cached.expired?
        end

        # Fetch JWKS
        response = HTTP::Client.get(jwks_uri)

        unless response.success?
          raise DecodeError.new("Failed to fetch JWKS from #{jwks_uri}: #{response.status}")
        end

        jwks = JWKSet.from_json(response.body)
        @jwks_cache[jwks_uri] = CachedData.new(jwks, @cache_ttl)
        jwks
      end
    end

    # Find a JWK by kid in a JWKS
    def find_key(jwks : JWKSet, kid : String) : JWK?
      jwks.keys.find { |key| key.kid == kid }
    end

    # Clear all caches
    def clear_cache : Nil
      @cache_mutex.synchronize do
        @metadata_cache.clear
        @jwks_cache.clear
      end
    end

    private def try_local_validation(
      token : String,
      header : Hash(String, JSON::Any),
      unverified_payload : JSON::Any,
      validate_claims : Bool,
    ) : JSON::Any?
      local_keys = @local_keys
      local_algorithm = @local_algorithm
      return nil unless local_keys && local_algorithm

      # Check if this is a local token (by kid or other heuristic)
      kid = header["kid"]?.try(&.as_s?)
      return nil unless kid

      key = local_keys[kid]?
      return nil unless key

      # Validate with local key
      payload, _ = JWT.decode(
        token,
        key: key,
        algorithm: local_algorithm,
        verify: true,
        validate: validate_claims
      )

      payload
    rescue e : JWT::DecodeError
      # Local validation failed, return nil to try JWKS
      nil
    end

    private def validate_with_jwks(
      token : String,
      header : Hash(String, JSON::Any),
      issuer : String?,
      audience : String | Array(String)?,
      validate_claims : Bool,
    ) : JSON::Any?
      # Get kid and alg from header
      kid = header["kid"]?.try(&.as_s)
      alg = header["alg"]?.try(&.as_s)

      raise DecodeError.new("Missing kid in JWT header") unless kid
      raise DecodeError.new("Missing alg in JWT header") unless alg

      # Parse algorithm
      algorithm = Algorithm.parse(alg)

      # Get JWKS URI from OIDC metadata or use issuer directly
      if issuer
        metadata = fetch_oidc_metadata(issuer)
        jwks_uri = metadata.jwks_uri
      else
        # Try to extract issuer from token
        unverified_payload, _ = JWT.decode(token, verify: false, validate: false)
        token_issuer = unverified_payload["iss"]?.try(&.as_s)
        raise DecodeError.new("No issuer provided and no iss claim in token") unless token_issuer

        metadata = fetch_oidc_metadata(token_issuer)
        jwks_uri = metadata.jwks_uri
      end

      # Fetch JWKS
      jwks = fetch_jwks(jwks_uri)

      # Find the key by kid
      jwk = find_key(jwks, kid)
      raise DecodeError.new("Key with kid #{kid} not found in JWKS") unless jwk

      # Convert JWK to PEM
      pem = jwk.to_pem

      # Validate the token
      payload, _ = JWT.decode(
        token,
        key: pem,
        algorithm: algorithm,
        verify: true,
        validate: validate_claims,
        aud: audience,
        iss: issuer
      )

      payload
    end

    # Validate scopes in a JWT payload
    #
    # @param payload JWT payload
    # @param required_scopes Required scopes (checks for "scp" claim)
    # @return true if all required scopes are present
    def self.validate_scopes(payload : JSON::Any, required_scopes : Array(String)) : Bool
      token_scopes = extract_scopes(payload)
      required_scopes.all? { |scope| token_scopes.includes?(scope) }
    end

    # Validate roles in a JWT payload
    #
    # @param payload JWT payload
    # @param required_roles Required roles (checks for "roles" claim)
    # @return true if all required roles are present
    def self.validate_roles(payload : JSON::Any, required_roles : Array(String)) : Bool
      token_roles = extract_roles(payload)
      required_roles.all? { |role| token_roles.includes?(role) }
    end

    # Extract scopes from JWT payload
    #
    # Checks both "scp" (Entra/Azure AD) and "scope" (standard) claims
    def self.extract_scopes(payload : JSON::Any) : Array(String)
      # Check "scp" claim (Entra/Azure AD format - array)
      if scp = payload["scp"]?.try(&.as_a?)
        return scp.map(&.as_s)
      end

      # Check "scope" claim (standard format - space-separated string)
      if scope = payload["scope"]?.try(&.as_s?)
        return scope.split(" ")
      end

      [] of String
    end

    # Extract roles from JWT payload
    #
    # Checks "roles" claim
    def self.extract_roles(payload : JSON::Any) : Array(String)
      if roles = payload["roles"]?.try(&.as_a?)
        return roles.map(&.as_s)
      end

      [] of String
    end
  end
end
