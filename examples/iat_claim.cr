require "../src/jwt"

# Create token with iat claim:
payload = {"foo" => "bar", "iat" => Time.utc.to_unix}
token = JWT.encode(payload, "SecretKey", JWT::Algorithm::HS256)
