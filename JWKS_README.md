# JWT JWKS Helper

A comprehensive JWKS (JSON Web Key Set) helper for JWT validation with support for OIDC discovery. This module is designed to work seamlessly with services like Microsoft Entra ID (Azure AD) and other OIDC-compliant identity providers.

## Features

- **OIDC Discovery**: Automatically fetches OIDC metadata from `/.well-known/openid-configuration`
- **JWKS Fetching**: Retrieves and caches JWKS from the discovered `jwks_uri`
- **Smart Caching**: Caches metadata and keys with configurable TTL (default: 10 minutes)
- **Local & Remote Tokens**: Supports both local service-to-service JWTs and remotely-issued tokens
- **Validation**: Validates `iss`, `aud`, `exp`, `nbf`, and signature
- **Scope & Role Enforcement**: Built-in helpers for checking scopes (`scp`) and roles
- **Thread-Safe**: Mutex-protected caching for concurrent access
- **Simple API**: Returns payload on success, `nil` on failure

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

### With Scope/Role Validation

```crystal
jwks = JWT::JWKS.new

# Validate the token first
payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  # Extract and check scopes (works with both "scp" array and "scope" string)
  scopes = JWT::JWKS.extract_scopes(payload)

  # Check for required scopes
  if scopes.includes?("read") && scopes.includes?("write")
    puts "User has required scopes"
  else
    puts "Missing required scopes"
  end
end
```

### Role-Based Validation

```crystal
payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  roles = JWT::JWKS.extract_roles(payload)

  if roles.includes?("admin")
    puts "User is an admin"
  else
    puts "Insufficient permissions"
  end
end
```

### Helper Method Validation

```crystal
payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  # Validate scopes using helper
  if JWT::JWKS.validate_scopes(payload, ["read", "write"])
    puts "Has all required scopes"
  end

  # Validate roles using helper
  if JWT::JWKS.validate_roles(payload, ["admin"])
    puts "Has admin role"
  end
end
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
  cache_ttl: 15.minutes  # Optional: customize cache TTL
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

# Manually fetch JWKS
jwks_data = jwks.fetch_jwks(metadata.jwks_uri)
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

## Entra ID / Azure AD Example

```crystal
require "jwt"

class TokenValidator
  def initialize(@tenant_id : String, @client_id : String)
    @jwks = JWT::JWKS.new(cache_ttl: 10.minutes)
    @issuer = "https://login.microsoftonline.com/#{@tenant_id}/v2.0"
  end

  def validate_entra_token(token : String, required_scopes : Array(String) = [] of String)
    payload = @jwks.validate(token, issuer: @issuer, audience: "api://#{@client_id}")
    return nil unless payload

    # Validate scopes
    if required_scopes.empty? || JWT::JWKS.validate_scopes(payload, required_scopes)
      payload
    else
      nil
    end
  end
end

# Usage
validator = TokenValidator.new(
  tenant_id: "your-tenant-id",
  client_id: "your-app-client-id"
)

token = request.headers["Authorization"]?.try(&.lstrip("Bearer "))
if token
  payload = validator.validate_entra_token(token, required_scopes: ["User.Read"])
  if payload
    # Token is valid, proceed
    user_id = payload["oid"].as_s  # Object ID
    user_email = payload["preferred_username"]?.try(&.as_s)
  else
    # Invalid token or missing scopes
    halt(401, "Unauthorized")
  end
end
```

## Helper Methods

### Scope Validation

```crystal
# Extract scopes from payload (checks both "scp" and "scope" claims)
scopes = JWT::JWKS.extract_scopes(payload)  # => ["read", "write"]

# Validate required scopes
JWT::JWKS.validate_scopes(payload, ["read", "write"])  # => true/false
```

### Role Validation

```crystal
# Extract roles from payload
roles = JWT::JWKS.extract_roles(payload)  # => ["admin", "user"]

# Validate required roles
JWT::JWKS.validate_roles(payload, ["admin"])  # => true/false
```

## Supported Algorithms

- **RSA**: RS256, RS384, RS512 (Primary use case for Entra ID)
- **HMAC**: HS256, HS384, HS512 (For local tokens)
- **ECDSA**: ES256, ES384, ES512 (Not yet implemented - will raise error)

## Architecture

The `JWT::JWKS` class provides a unified interface for:

1. **Local token validation**: For service-to-service JWTs using shared secrets
2. **Remote token validation**: For JWTs issued by external identity providers via JWKS

### Validation Flow

```
Token arrives
    ↓
Extract header (kid, alg)
    ↓
Try local validation?
    ├─ Yes → Validate with local key
    └─ No  → Fetch OIDC metadata (cached)
                ↓
             Fetch JWKS (cached)
                ↓
             Find key by kid
                ↓
             Convert JWK to PEM
                ↓
             Validate signature
                ↓
             Validate claims (exp, nbf, iss, aud)
    ↓
Return payload or nil
```

## Error Handling

The `validate` method returns `nil` on any validation failure, making it safe to use in conditionals:

```crystal
if payload = jwks.validate(token, issuer: issuer)
  # Token is valid
else
  # Token is invalid (signature, expired, wrong issuer, etc.)
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

Comprehensive specs are included in `spec/integration/jwks_spec.cr`. Run them with:

```bash
crystal spec spec/integration/jwks_spec.cr
```

The specs cover:
- JWK parsing and conversion to PEM
- OIDC metadata fetching
- JWKS fetching and caching
- Local JWT validation
- Remote JWT validation via JWKS
- Scope and role extraction/validation
- Error handling (expired tokens, invalid signatures, missing keys, etc.)

## Security Considerations

1. **Cache TTL**: The default 10-minute cache helps balance performance and security. Adjust based on your key rotation frequency.
2. **HTTPS Only**: Always use HTTPS for OIDC metadata and JWKS endpoints in production.
3. **Scope Validation**: Always validate scopes/roles in your callback to enforce proper authorization.
4. **Token Expiration**: Standard claim validation (exp, nbf) is enabled by default - don't disable it in production.

## Limitations

- **EC Keys**: ECDSA keys (ES256/ES384/ES512) are not yet fully supported
- **Key Rotation**: Cache is time-based; consider implementing event-based invalidation for key rotation events

## Contributing

This module is part of the Crystal JWT shard. Contributions are welcome!

## License

MIT License - see LICENSE file for details
