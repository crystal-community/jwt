require "json"
require "http/client"
require "../jwt"
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
    # Allowed algorithms for JWKS validation (interoperable with real-world JWKS endpoints)
    # "none" is explicitly excluded for security
    ALLOWED_ALGORITHMS = {
      "RS256", "RS384", "RS512",
      "PS256", "PS384", "PS512",
      "ES256", "ES384", "ES512",
      "EdDSA",
    }

    # Cached metadata and keys
    private struct CachedData(T)
      property data : T
      property expires_at : Time
      property etag : String?

      def initialize(@data : T, ttl : Time::Span, @etag : String? = nil)
        @expires_at = Time.utc + ttl
      end

      def expired? : Bool
        Time.utc >= @expires_at
      end
    end

    # Default cache TTL (10 minutes)
    DEFAULT_CACHE_TTL = 10.minutes

    # Default leeway for time-based claims (60 seconds)
    DEFAULT_LEEWAY = 60.seconds

    # Local keys for service-to-service JWT validation
    getter local_keys : Hash(String, String)?
    getter local_algorithm : Algorithm?

    # Cache TTL
    getter cache_ttl : Time::Span

    # Clock skew leeway for time-based claims (exp, nbf, iat)
    property leeway : Time::Span

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
    # @param leeway Clock skew leeway for time-based claims (default: 60 seconds)
    def initialize(
      @local_keys : Hash(String, String)? = nil,
      @local_algorithm : Algorithm? = nil,
      @cache_ttl : Time::Span = DEFAULT_CACHE_TTL,
      @leeway : Time::Span = DEFAULT_LEEWAY,
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
      # Security: enforce HTTPS for issuer
      issuer_uri = URI.parse(issuer)
      unless issuer_uri.scheme == "https"
        raise DecodeError.new("Issuer must use HTTPS, got: #{issuer_uri.scheme}")
      end

      @cache_mutex.synchronize do
        # Check cache first
        if cached = @metadata_cache[issuer]?
          return cached.data unless cached.expired?
        end

        # Fetch from well-known endpoint
        well_known_url = "#{issuer.rstrip("/")}/.well-known/openid-configuration"
        uri = URI.parse(well_known_url)

        # Prepare HTTP client with timeouts
        client = HTTP::Client.new(uri)
        client.connect_timeout = 3.seconds
        client.read_timeout = 5.seconds

        response = client.get(uri.request_target)

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
    # @param force_refresh Force refresh even if cached (used for key rotation)
    # @return JWKS key set
    def fetch_jwks(jwks_uri : String, force_refresh : Bool = false) : JWKSet
      uri = URI.parse(jwks_uri)

      # Security: enforce HTTPS
      unless uri.scheme == "https"
        raise DecodeError.new("JWKS URI must use HTTPS, got: #{uri.scheme}")
      end

      @cache_mutex.synchronize do
        # Check cache first (unless force refresh)
        if !force_refresh
          if cached = @jwks_cache[jwks_uri]?
            return cached.data unless cached.expired?
          end
        end

        # Prepare HTTP client with timeouts
        client = HTTP::Client.new(uri)
        client.connect_timeout = 3.seconds
        client.read_timeout = 5.seconds

        # Add conditional GET headers if we have cached data
        headers = HTTP::Headers.new
        if cached = @jwks_cache[jwks_uri]?
          if etag = cached.etag
            headers["If-None-Match"] = etag
          end
        end

        # Fetch JWKS
        response = client.get(uri.request_target, headers)

        case response.status_code
        when 304
          # Not modified, use cached data
          if cached = @jwks_cache[jwks_uri]?
            return cached.data
          end
          # Fallthrough to error if no cache
          raise DecodeError.new("Received 304 but no cached data available")
        when 200
          jwks = JWKSet.from_json(response.body)

          # Parse Cache-Control for TTL
          ttl = @cache_ttl
          if cache_control = response.headers["Cache-Control"]?
            if max_age = parse_max_age(cache_control)
              ttl = max_age
            end
          end

          # Store with ETag if present
          etag = response.headers["ETag"]?
          @jwks_cache[jwks_uri] = CachedData.new(jwks, ttl, etag)
          jwks
        else
          raise DecodeError.new("Failed to fetch JWKS from #{jwks_uri}: #{response.status}")
        end
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

    # Pick and validate algorithm from JWK and header
    # Security: don't trust alg from header alone - validate against JWK
    private def pick_algorithm_from_jwk(jwk : JWK, header_alg : String) : Algorithm
      # Reject "none" algorithm
      if header_alg.downcase == "none"
        raise DecodeError.new("Algorithm 'none' is not allowed")
      end

      # Check against allow-list
      unless ALLOWED_ALGORITHMS.includes?(header_alg)
        raise DecodeError.new("Algorithm '#{header_alg}' is not in the allow-list")
      end

      # If JWK has alg field, it must match header alg
      if jwk_alg = jwk.alg
        unless jwk_alg == header_alg
          raise DecodeError.new("Algorithm mismatch: JWK alg='#{jwk_alg}' != header alg='#{header_alg}'")
        end
      end

      # Validate kty/curve compatibility with algorithm
      case jwk.kty
      when "RSA"
        # RS256/RS384/RS512 or PS256/PS384/PS512
        unless header_alg.starts_with?("RS") || header_alg.starts_with?("PS")
          raise DecodeError.new("Algorithm '#{header_alg}' incompatible with JWK kty='RSA'")
        end
      when "EC"
        # ES256/ES384/ES512 (+ ES256K)
        unless header_alg.starts_with?("ES")
          raise DecodeError.new("Algorithm '#{header_alg}' incompatible with JWK kty='EC'")
        end
        # Validate curve matches algorithm
        if crv = jwk.crv
          expected_crv = case header_alg
                         when "ES256"
                           "P-256"
                         when "ES384"
                           "P-384"
                         when "ES512"
                           "P-521"
                         when "ES256K"
                           "secp256k1"
                         else
                           nil
                         end
          if expected_crv && crv != expected_crv
            raise DecodeError.new("EC curve mismatch: JWK crv='#{crv}' incompatible with alg='#{header_alg}'")
          end
        end
      when "OKP"
        # EdDSA with Ed25519
        unless header_alg == "EdDSA"
          raise DecodeError.new("Algorithm '#{header_alg}' incompatible with JWK kty='OKP'")
        end
        if crv = jwk.crv
          unless crv == "Ed25519"
            raise DecodeError.new("Only Ed25519 curve is supported for OKP keys, got: #{crv}")
          end
        end
      else
        raise DecodeError.new("Unsupported JWK kty: #{jwk.kty}")
      end

      # Validate key usage if present
      if use = jwk.use
        unless use == "sig"
          raise DecodeError.new("JWK use='#{use}' is not valid for signature verification (expected 'sig')")
        end
      end

      # Validate key_ops if present
      if key_ops = jwk.key_ops
        unless key_ops.includes?("verify")
          raise DecodeError.new("JWK key_ops does not include 'verify' operation")
        end
      end

      Algorithm.parse(header_alg)
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
      x5t = header["x5t"]?.try(&.as_s)
      typ = header["typ"]?.try(&.as_s)

      raise DecodeError.new("Missing alg in JWT header") unless alg

      # Validate typ if present (allow JWT or at+jwt)
      if typ
        typ_lower = typ.downcase
        unless typ_lower == "jwt" || typ_lower == "at+jwt"
          raise DecodeError.new("Invalid typ: '#{typ}'. Expected 'JWT' or 'at+jwt'")
        end
      end

      # Get token issuer for validation
      unverified_payload, _ = JWT.decode(token, verify: false, validate: false)
      token_issuer = unverified_payload["iss"]?.try(&.as_s)
      raise DecodeError.new("Missing iss claim in token") unless token_issuer

      # Fetch OIDC metadata using token's issuer
      metadata = fetch_oidc_metadata(token_issuer)
      jwks_uri = metadata.jwks_uri

      # Strict issuer validation: token iss must match metadata issuer
      unless token_issuer == metadata.issuer
        raise DecodeError.new("Token iss='#{token_issuer}' does not match metadata issuer='#{metadata.issuer}'")
      end

      # If caller provided issuer, validate it matches token issuer
      if issuer && issuer != token_issuer
        raise DecodeError.new("Provided issuer='#{issuer}' does not match token iss='#{token_issuer}'")
      end

      # Fetch JWKS
      jwks = fetch_jwks(jwks_uri)

      # Find the key by kid, x5t, or try all compatible keys
      jwk : JWK? = nil

      if kid
        jwk = find_key(jwks, kid)
        # If kid not found, try refreshing cache (key rotation scenario)
        unless jwk
          jwks = fetch_jwks(jwks_uri, force_refresh: true)
          jwk = find_key(jwks, kid)
        end
      elsif x5t
        # Try matching by x5t thumbprint
        jwk = jwks.keys.find { |k| k.x5t == x5t || k.x5t_s256 == x5t }
      end

      # Last resort: if no kid/x5t, try all keys of compatible type (bounded)
      unless jwk
        compatible_keys = jwks.keys.select do |k|
          begin
            # Only try keys that could work with this algorithm
            case k.kty
            when "RSA"
              alg.starts_with?("RS") || alg.starts_with?("PS")
            when "EC"
              alg.starts_with?("ES")
            when "OKP"
              alg == "EdDSA"
            else
              false
            end
          rescue
            false
          end
        end

        # Try each compatible key (limit to first 5 to prevent DoS)
        compatible_keys.first(5).each do |candidate_key|
          begin
            algorithm = pick_algorithm_from_jwk(candidate_key, alg)
            pem = candidate_key.to_pem
            payload, _ = JWT.decode(
              token,
              key: pem,
              algorithm: algorithm,
              verify: true,
              validate: validate_claims,
              aud: audience,
              iss: token_issuer
            )
            return payload
          rescue
            # Try next key
            next
          end
        end

        raise DecodeError.new("No valid key found for token verification")
      end

      # Validate algorithm against JWK
      algorithm = pick_algorithm_from_jwk(jwk, alg)

      # Convert JWK to PEM/key format
      pem = jwk.to_pem

      # Validate the token
      payload, _ = JWT.decode(
        token,
        key: pem,
        algorithm: algorithm,
        verify: true,
        validate: validate_claims,
        aud: audience,
        iss: token_issuer
      )

      payload
    end

    # Parse max-age from Cache-Control header
    private def parse_max_age(cache_control : String) : Time::Span?
      # Parse "max-age=3600" directive
      if match = cache_control.match(/max-age=(\d+)/)
        seconds = match[1].to_i
        seconds.seconds
      end
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
    # Checks "scp" (Entra/Azure AD), "scope" (standard), and "permissions" (Auth0) claims
    # Handles both space-delimited strings and arrays
    def self.extract_scopes(payload : JSON::Any) : Array(String)
      # Check "scp" claim (Entra/Azure AD)
      # In Entra, scp is typically a SPACE-DELIMITED STRING, not an array
      if scp_s = payload["scp"]?.try(&.as_s?)
        return scp_s.split(' ')
      elsif scp_a = payload["scp"]?.try(&.as_a?)
        # Some providers may use array format
        return scp_a.map(&.as_s)
      end

      # Check "scope" claim (standard OAuth/OIDC - space-separated string)
      if scope_s = payload["scope"]?.try(&.as_s?)
        return scope_s.split(' ')
      elsif scope_a = payload["scope"]?.try(&.as_a?)
        # Array format (less common)
        return scope_a.map(&.as_s)
      end

      # Check "permissions" claim (Auth0)
      if perms = payload["permissions"]?.try(&.as_a?)
        return perms.map(&.as_s)
      end

      [] of String
    end

    # Extract roles from JWT payload
    #
    # Checks "roles" (Azure AD), "realm_access.roles" (Keycloak realm roles),
    # "resource_access" (Keycloak client roles), and "groups" (Okta) claims
    def self.extract_roles(payload : JSON::Any) : Array(String)
      # Check "roles" claim (Azure AD app roles, standard)
      if roles = payload["roles"]?.try(&.as_a?)
        return roles.map(&.as_s)
      end

      # Check Keycloak realm roles (realm_access.roles)
      if realm_access = payload["realm_access"]?
        if realm_roles = realm_access["roles"]?.try(&.as_a?)
          return realm_roles.map(&.as_s)
        end
      end

      # Check Keycloak resource/client roles (resource_access)
      # Flatten all client roles into a single array
      if resource_access = payload["resource_access"]?.try(&.as_h?)
        all_roles = [] of String
        resource_access.each_value do |client|
          if client_roles = client["roles"]?.try(&.as_a?)
            all_roles.concat(client_roles.map(&.as_s))
          end
        end
        return all_roles unless all_roles.empty?
      end

      # Check Okta groups (sometimes used for authorization)
      if groups = payload["groups"]?.try(&.as_a?)
        return groups.map(&.as_s)
      end

      [] of String
    end
  end
end
