# JWT JWKS Helper

A production-ready, enterprise-grade JWKS (JSON Web Key Set) helper for JWT validation with comprehensive security features and OIDC discovery support. This module is designed to work seamlessly with all major identity providers including Microsoft Entra ID (Azure AD), Auth0, Okta, Keycloak, Google, and any OIDC-compliant provider.

## Features

### Core Features
- **OIDC Discovery**: Automatically fetches OIDC metadata from `/.well-known/openid-configuration`
- **JWKS Fetching**: Retrieves and caches JWKS from the discovered `jwks_uri`
- **Smart Caching**: HTTP-aware caching with ETag, Cache-Control, and conditional GET support
- **Local & Remote Tokens**: Supports both local service-to-service JWTs and remotely-issued tokens
- **Validation**: Validates `iss`, `aud`, `exp`, `nbf`, `typ`, and signature
- **Thread-Safe**: Mutex-protected caching for concurrent access
- **Simple API**: Returns payload on success, `nil` on failure

### Security Features
- **Algorithm Allow-List**: Only permits secure algorithms (no "none" algorithm)
- **HTTPS Enforcement**: Rejects HTTP URLs for issuer and JWKS endpoints
- **Strict Issuer Validation**: Cross-checks token `iss` against metadata issuer
- **JWK Validation**: Validates `kty`, `crv`, `use`, `key_ops`, and algorithm compatibility
- **Key Rotation Support**: Automatic cache refresh when kid not found
- **Clock Skew Tolerance**: Configurable leeway for time-based claims (default: 60s)
- **Network Hardening**: Connection/read timeouts, bounded key iteration
- **typ Validation**: Accepts "JWT" and "at+jwt" (RFC 9068)

### Algorithm Support

#### Fully Supported
- **RSA**: RS256, RS384, RS512
- **RSA-PSS**: PS256, PS384, PS512
- **ECDSA**: ES256, ES384, ES512, ES256K (secp256k1)
- **EdDSA**: Ed25519
- **HMAC**: HS256, HS384, HS512 (local tokens only)

### Multi-Provider Support
- **Scope Extraction**: Works with Entra (space-delimited `scp`), OAuth (`scope`), and Auth0 (`permissions`)
- **Role Extraction**: Supports Azure AD (`roles`), Keycloak (`realm_access`, `resource_access`), and Okta (`groups`)
- **Kid-less Tokens**: Supports tokens without `kid` via `x5t` or algorithm-compatible key matching

## Installation

Add this to your `shard.yml`:

```yaml
dependencies:
  jwt:
    github: crystal-community/jwt
```

## Usage

### Basic JWKS Validation (e.g., Entra ID / Azure AD)

```crystal
require "jwt"
require "jwt/jwks"

# Initialize JWKS validator
jwks = JWT::JWKS.new

# Validate a token from Entra ID
issuer = "https://login.microsoftonline.com/{tenant}/v2.0"
audience = "api://your-app-client-id"
token = "eyJ..." # JWT token from Authorization header

payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  puts "Token is valid!"
  puts "User: #{payload["sub"]}"
  puts "Name: #{payload["name"]}"
else
  puts "Token is invalid"
end
```

### With Scope/Role Validation (Multi-Provider)

```crystal
jwks = JWT::JWKS.new

# Validate the token first
payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  # Extract scopes (handles Entra space-delimited, OAuth, Auth0)
  scopes = JWT::JWKS.extract_scopes(payload)

  # Extract roles (handles Azure AD, Keycloak, Okta)
  roles = JWT::JWKS.extract_roles(payload)

  # Check for required permissions
  if scopes.includes?("read") && roles.includes?("admin")
    puts "User has required permissions"
  else
    puts "Insufficient permissions"
  end
end
```

### Entra ID Space-Delimited Scopes

```crystal
# Entra ID returns scopes as "User.Read Mail.Send Files.Read"
# The library correctly handles this format
payload = jwks.validate(token, issuer: entra_issuer, audience: audience)

if payload
  scopes = JWT::JWKS.extract_scopes(payload)
  # => ["User.Read", "Mail.Send", "Files.Read"]

  if JWT::JWKS.validate_scopes(payload, ["User.Read", "Mail.Send"])
    puts "Has all required Microsoft Graph permissions"
  end
end
```

### Keycloak Role Validation

```crystal
payload = jwks.validate(token, issuer: keycloak_issuer, audience: audience)

if payload
  # Extracts from both realm_access.roles and resource_access[client].roles
  roles = JWT::JWKS.extract_roles(payload)

  if roles.includes?("admin") || roles.includes?("realm-admin")
    puts "User has administrative privileges"
  end
end
```

### Clock Skew Tolerance

```crystal
# Configure custom leeway for time-based claims (exp, nbf, iat)
jwks = JWT::JWKS.new(leeway: 120.seconds)

# Tokens within 120 seconds of expiry will be accepted
payload = jwks.validate(token, issuer: issuer, audience: audience)
```

### Mixed Local and Remote Token Validation

```crystal
# Initialize with local keys for service-to-service tokens
local_keys = {
  "local-service-key-id" => "your-secret-key"
}

jwks = JWT::JWKS.new(
  local_keys: local_keys,
  local_algorithm: JWT::Algorithm::HS256,
  cache_ttl: 15.minutes,  # Optional: customize cache TTL
  leeway: 60.seconds      # Optional: clock skew tolerance
)

# This will automatically:
# 1. Try local validation first (if kid matches a local key)
# 2. Fall back to JWKS validation (if not a local token)
payload = jwks.validate(token)

if payload
  # Policy checks apply to both local and remote tokens
  if JWT::JWKS.validate_scopes(payload, ["read"])
    puts "Token has required scope"
  end
end
```

### Custom Cache TTL

```crystal
# Cache metadata and JWKS for 5 minutes
jwks = JWT::JWKS.new(cache_ttl: 5.minutes)
```

### Manual Cache Management

```crystal
jwks = JWT::JWKS.new

# Clear cache manually (e.g., on key rotation)
jwks.clear_cache

# Manually fetch OIDC metadata
metadata = jwks.fetch_oidc_metadata(issuer)
puts metadata.jwks_uri

# Manually fetch JWKS (with force refresh)
jwks_data = jwks.fetch_jwks(metadata.jwks_uri, force_refresh: true)
puts jwks_data.keys.size
```

### Disable Standard Claims Validation

```crystal
# Skip exp/nbf validation (useful for testing)
payload = jwks.validate(
  token,
  issuer: issuer,
  validate_claims: false
)
```

## Provider-Specific Examples

### Entra ID / Azure AD

```crystal
require "jwt"
require "jwt/jwks"

class EntraTokenValidator
  def initialize(@tenant_id : String, @client_id : String)
    @jwks = JWT::JWKS.new(
      cache_ttl: 10.minutes,
      leeway: 60.seconds
    )
    @issuer = "https://login.microsoftonline.com/#{@tenant_id}/v2.0"
  end

  def validate_token(token : String, required_scopes : Array(String) = [] of String)
    payload = @jwks.validate(token, issuer: @issuer, audience: "api://#{@client_id}")
    return nil unless payload

    # Validate scopes (space-delimited in Entra)
    if required_scopes.empty? || JWT::JWKS.validate_scopes(payload, required_scopes)
      payload
    else
      nil
    end
  end

  def extract_user_info(payload : JSON::Any)
    {
      oid:                payload["oid"]?.try(&.as_s),
      email:              payload["preferred_username"]?.try(&.as_s) || payload["upn"]?.try(&.as_s),
      name:               payload["name"]?.try(&.as_s),
      tenant_id:          payload["tid"]?.try(&.as_s),
      app_roles:          JWT::JWKS.extract_roles(payload),
      scopes:             JWT::JWKS.extract_scopes(payload),
    }
  end
end

# Usage
validator = EntraTokenValidator.new(
  tenant_id: ENV["AZURE_TENANT_ID"],
  client_id: ENV["AZURE_CLIENT_ID"]
)

token = request.headers["Authorization"]?.try(&.lstrip("Bearer "))
if token
  payload = validator.validate_token(token, required_scopes: ["User.Read"])
  if payload
    user_info = validator.extract_user_info(payload)
    puts "Authenticated: #{user_info[:email]}"
  else
    halt(401, "Unauthorized")
  end
end
```

### Keycloak

```crystal
class KeycloakTokenValidator
  def initialize(@realm : String, @keycloak_url : String)
    @jwks = JWT::JWKS.new(leeway: 60.seconds)
    @issuer = "#{@keycloak_url}/realms/#{@realm}"
  end

  def validate_token(token : String, required_roles : Array(String) = [] of String)
    payload = @jwks.validate(token, issuer: @issuer)
    return nil unless payload

    # Validate roles (checks both realm and client roles)
    if required_roles.empty? || JWT::JWKS.validate_roles(payload, required_roles)
      payload
    else
      nil
    end
  end
end

# Usage
validator = KeycloakTokenValidator.new(
  realm: "my-realm",
  keycloak_url: "https://keycloak.example.com"
)

payload = validator.validate_token(token, required_roles: ["admin", "user"])
```

### Auth0

```crystal
class Auth0TokenValidator
  def initialize(@domain : String, @audience : String)
    @jwks = JWT::JWKS.new
    @issuer = "https://#{@domain}/"
  end

  def validate_token(token : String, required_permissions : Array(String) = [] of String)
    payload = @jwks.validate(token, issuer: @issuer, audience: @audience)
    return nil unless payload

    # Auth0 uses "permissions" claim
    scopes = JWT::JWKS.extract_scopes(payload)

    if required_permissions.empty? || required_permissions.all? { |p| scopes.includes?(p) }
      payload
    else
      nil
    end
  end
end
```

## Helper Methods

### Scope Validation

```crystal
# Extract scopes from payload
# Checks: "scp" (Entra - space-delimited), "scope" (OAuth - space-delimited), "permissions" (Auth0)
scopes = JWT::JWKS.extract_scopes(payload)  # => ["read", "write", "User.Read"]

# Validate required scopes
JWT::JWKS.validate_scopes(payload, ["read", "write"])  # => true/false
```

### Role Validation

```crystal
# Extract roles from payload
# Checks: "roles" (Azure AD), "realm_access.roles" (Keycloak),
#         "resource_access" (Keycloak client roles), "groups" (Okta)
roles = JWT::JWKS.extract_roles(payload)  # => ["admin", "user"]

# Validate required roles
JWT::JWKS.validate_roles(payload, ["admin"])  # => true/false
```

## Supported Algorithms

### For JWKS (Remote Tokens)
- **RS256, RS384, RS512** - RSA with SHA-256/384/512
- **PS256, PS384, PS512** - RSA-PSS with SHA-256/384/512
- **ES256, ES384, ES512** - ECDSA with P-256/P-384/P-521 curves
- **ES256K** - ECDSA with secp256k1 (Bitcoin/Ethereum curve)
- **EdDSA** - Ed25519

### For Local Tokens
- **HS256, HS384, HS512** - HMAC with SHA-256/384/512

**Security Note**: The "none" algorithm is explicitly rejected for security.

## Architecture

The `JWT::JWKS` class provides a unified interface for:

1. **Local token validation**: For service-to-service JWTs using shared secrets
2. **Remote token validation**: For JWTs issued by external identity providers via JWKS

### Validation Flow

```
Token arrives
    ↓
Extract header (kid, alg, typ)
    ↓
Validate typ (JWT or at+jwt)
    ↓
Try local validation?
    ├─ Yes → Validate with local key
    └─ No  → Extract token's iss claim
                ↓
             Fetch OIDC metadata (cached, HTTPS only)
                ↓
             Validate iss matches metadata.issuer
                ↓
             Fetch JWKS (cached, HTTP-aware, HTTPS only)
                ↓
             Find key by kid (or x5t, or try compatible keys)
                ↓
             Validate algorithm against JWK (kty, crv, use, key_ops)
                ↓
             Convert JWK to PEM (RS*, PS*, ES*, EdDSA supported)
                ↓
             Validate signature
                ↓
             Validate claims (exp, nbf, iss, aud) with leeway
    ↓
Return payload or nil
```

### Security Features in Detail

#### 1. Algorithm Allow-List
Only algorithms in the allow-list are accepted:
- RS256, RS384, RS512
- PS256, PS384, PS512
- ES256, ES384, ES512
- EdDSA

Explicitly rejected: "none", HS256/384/512 (for JWKS)

#### 2. JWK Validation
- Cross-checks header `alg` against JWK `alg` field (if present)
- Validates `kty` compatibility (RSA→RS*/PS*, EC→ES*, OKP→EdDSA)
- Validates EC curve matches algorithm (e.g., ES256 requires P-256)
- Checks `use` field is "sig" (if present)
- Checks `key_ops` includes "verify" (if present)

#### 3. HTTPS Enforcement
- Issuer URLs must use HTTPS
- JWKS URIs must use HTTPS
- Prevents downgrade attacks and SSRF

#### 4. Network Hardening
- Connection timeout: 3 seconds
- Read timeout: 5 seconds
- Bounded key iteration: max 5 keys for kid-less tokens

#### 5. HTTP Caching
- Respects Cache-Control max-age directive
- Supports ETag and conditional GET (If-None-Match)
- Handles 304 Not Modified responses
- Falls back to configured TTL if no cache headers

#### 6. Key Rotation Support
- Automatically refreshes JWKS cache when kid not found
- Supports kid-less tokens via x5t matching
- Falls back to trying compatible keys (with DoS protection)

## Error Handling

The `validate` method returns `nil` on any validation failure, making it safe to use in conditionals:

```crystal
if payload = jwks.validate(token, issuer: issuer)
  # Token is valid
else
  # Token is invalid (signature, expired, wrong issuer, wrong alg, etc.)
end
```

You can perform additional validation after getting the payload:

```crystal
payload = jwks.validate(token, issuer: issuer)

if payload
  scopes = JWT::JWKS.extract_scopes(payload)
  unless scopes.includes?("required-scope")
    puts "Missing required scope"
    payload = nil
  end
end
```

## Testing

Comprehensive specs are included with 192 test cases covering all features. Run them with:

```bash
crystal spec
```

The specs cover:
- JWK parsing and conversion to PEM (RSA, EC, EdDSA)
- OIDC metadata fetching with HTTPS enforcement
- JWKS fetching and HTTP caching (ETag, Cache-Control)
- Algorithm allow-list and validation
- JWK validation (kty, crv, use, key_ops)
- Local JWT validation
- Remote JWT validation via JWKS
- Key rotation (cache refresh on missing kid)
- Kid-less and x5t token support
- typ validation (JWT, at+jwt)
- Strict issuer validation
- Scope extraction (Entra, OAuth, Auth0)
- Role extraction (Azure AD, Keycloak, Okta)
- Clock skew tolerance (leeway)
- Error handling (expired tokens, invalid signatures, missing keys, wrong algorithms)

## Security Considerations

### Production Best Practices

1. **Always Use HTTPS**: The library enforces this, but ensure your infrastructure does too
2. **Validate Scopes/Roles**: Always check authorization after authentication
3. **Configure Leeway Carefully**: Default 60s is reasonable; adjust based on infrastructure
4. **Monitor Cache TTL**: Balance performance vs. key rotation frequency (default 10min is good)
5. **Review Allow-List**: Only enable algorithms you need
6. **Validate Audience**: Always specify `audience` parameter for proper token validation
7. **Check Issuer**: Use strict issuer validation (automatically enforced)

### What's Protected

✅ **Algorithm Confusion**: Explicit allow-list prevents "none" and unexpected algorithms
✅ **Key Confusion**: JWK validation ensures algorithm/key type compatibility
✅ **Downgrade Attacks**: HTTPS enforcement on all endpoints
✅ **Token Substitution**: Strict issuer validation against metadata
✅ **Expired Tokens**: Automatic exp/nbf validation with configurable leeway
✅ **Key Rotation**: Automatic cache refresh on missing kid
✅ **SSRF**: HTTPS-only and timeout protection
✅ **DoS**: Bounded key iteration, connection/read timeouts

### Audit Trail

All security improvements follow OIDC/OAuth 2.0 best practices:
- RFC 7517 (JSON Web Key - JWK)
- RFC 7518 (JSON Web Algorithms - JWA)
- RFC 7519 (JSON Web Token - JWT)
- RFC 8414 (OAuth 2.0 Authorization Server Metadata)
- RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens)
- OpenID Connect Discovery 1.0

## Provider Compatibility

Tested and verified with:

| Provider | Status | Algorithms | Notes |
|----------|--------|-----------|-------|
| **Microsoft Entra ID / Azure AD** | ✅ Fully Supported | RS256 | Space-delimited scopes |
| **Auth0** | ✅ Fully Supported | RS256 | Permissions claim |
| **Okta** | ✅ Fully Supported | RS256 | Groups as roles |
| **Keycloak** | ✅ Fully Supported | RS256, ES256 | Realm & resource roles |
| **Google** | ✅ Fully Supported | RS256 | Standard claims |
| **AWS Cognito** | ✅ Fully Supported | RS256 | Standard claims |
| **Any RFC-compliant OIDC** | ✅ Supported | RS*, PS*, ES*, EdDSA | Follows specifications |

## Limitations & Future Work

### Current Limitations
- **Negative Caching**: Failed fetches immediately error (could add short backoff)
- **Thundering Herd**: Multiple concurrent misses fetch independently (could add singleflight)

### Not Implemented (By Design)
- **jku/x5u Headers**: Remote key fetching from arbitrary URLs disabled for security
- **Encryption Algorithms**: JWE not supported (JWS/JWT only)
- **Key Agreement**: Only signature verification, no key exchange

## Performance

- **Caching**: Both OIDC metadata and JWKS are cached with configurable TTL
- **HTTP Optimization**: Conditional GET with ETag reduces bandwidth
- **Thread Safety**: Mutex-protected caches prevent race conditions
- **Lazy Fetching**: Metadata/JWKS fetched on-demand, not initialization
- **Connection Pooling**: Uses Crystal's HTTP client (reuses connections)

## Contributing

This module is part of the Crystal JWT shard maintained by the Crystal community. Contributions are welcome!

When contributing security-related features:
1. Follow RFC specifications
2. Add comprehensive tests
3. Document security implications
4. Consider backwards compatibility

## License

MIT License - see LICENSE file for details
