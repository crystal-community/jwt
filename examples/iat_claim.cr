require "../src/jwt"

# Create token with iat claim:
payload = { "foo" => "bar", "iat" => Time.now.epoch }
token = JWT.encode(payload, "SecretKey", "HS256")
