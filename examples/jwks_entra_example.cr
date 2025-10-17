require "../src/jwt"

# Example: Validating Entra ID (Azure AD) JWTs with JWKS
#
# This example demonstrates how to validate JWTs issued by Microsoft Entra ID
# using the JWKS helper with OIDC discovery.

# Configuration for your Entra ID tenant
TENANT_ID = ENV["ENTRA_TENANT_ID"]? || "your-tenant-id"
CLIENT_ID = ENV["ENTRA_CLIENT_ID"]? || "your-app-client-id"

# Entra ID issuer URL
issuer = "https://login.microsoftonline.com/#{TENANT_ID}/v2.0"

# Expected audience (your API's client ID)
audience = "api://#{CLIENT_ID}"

# Initialize JWKS validator
jwks = JWT::JWKS.new(cache_ttl: 10.minutes)

# Example token (replace with a real token from an Authorization header)
# In a real application, you'd get this from:
# token = request.headers["Authorization"]?.try(&.lstrip("Bearer "))
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImJlZDdmM2VhLWQ5YzAtNGU5MS04NDU1LWQ2NTYwNGE0YjAzMCJ9..."

puts "Validating Entra ID JWT..."
puts

# Basic validation (signature, exp, nbf, iss, aud)
payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  puts "✓ Token is valid!"
  puts
  puts "Token claims:"
  puts "  Subject (oid): #{payload["oid"]?}"
  puts "  Username: #{payload["preferred_username"]?}"
  puts "  Name: #{payload["name"]?}"
  puts "  Email: #{payload["email"]?}"
else
  puts "✗ Token is invalid"
  exit 1
end

puts
puts "---"
puts

# Validation with scope checking
puts "Validating with scope requirements..."

required_scopes = ["User.Read", "Mail.Read"]

payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  # Extract scopes (Entra uses "scp" claim as an array)
  scopes = JWT::JWKS.extract_scopes(payload)

  puts "  Token scopes: #{scopes}"
  puts "  Required scopes: #{required_scopes}"

  # Check if all required scopes are present
  if JWT::JWKS.validate_scopes(payload, required_scopes)
    puts "  ✓ All required scopes present"
    puts
    puts "Token validated successfully with required scopes!"
  else
    missing = required_scopes.reject { |scope| scopes.includes?(scope) }
    puts "  ✗ Missing scopes: #{missing}"
    puts
    puts "Token validation failed (missing scopes)"
    exit 1
  end
else
  puts
  puts "Token validation failed (invalid token)"
  exit 1
end

puts
puts "---"
puts

# Role-based validation (if your app uses app roles)
puts "Validating with role requirements..."

required_roles = ["Admin"]

payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  roles = JWT::JWKS.extract_roles(payload)

  puts "  Token roles: #{roles}"
  puts "  Required roles: #{required_roles}"

  if roles.any? { |role| required_roles.includes?(role) }
    puts "  ✓ User has required role"
    puts
    puts "Token validated successfully with required roles!"
  else
    puts "  ✗ User doesn't have required role"
    puts
    puts "Token validation failed (missing roles)"
  end
else
  puts
  puts "Token validation failed (invalid token)"
end

puts
puts "---"
puts

# Helper methods for scope/role checking
puts "Using helper methods..."

payload = jwks.validate(token, issuer: issuer, audience: audience)

if payload
  # Check specific scopes
  has_user_read = JWT::JWKS.validate_scopes(payload, ["User.Read"])
  has_mail_send = JWT::JWKS.validate_scopes(payload, ["Mail.Send"])

  puts "  Has User.Read scope: #{has_user_read}"
  puts "  Has Mail.Send scope: #{has_mail_send}"

  # Check specific roles
  is_admin = JWT::JWKS.validate_roles(payload, ["Admin"])
  is_user = JWT::JWKS.validate_roles(payload, ["User"])

  puts "  Is Admin: #{is_admin}"
  puts "  Is User: #{is_user}"
end
