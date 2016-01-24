require "../src/jwt"

# Create token that will become acceptable in 1 minute
nbf = Time.now.epoch + 60
payload = { "foo" => "bar", "nbf" => nbf }
token = JWT.encode(payload, "SecretKey", "HS256")

# Currently it's not acceptable, raises JWT::ImmatureSignatureError
JWT.decode(token, "SecretKey", "HS256")
