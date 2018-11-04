require "../src/jwt"

# Create token with iat claim:
payload = {"foo" => "bar", "iat" => Time.now.to_unix}
token = JWT.encode(payload, "SecretKey", "HS256")
