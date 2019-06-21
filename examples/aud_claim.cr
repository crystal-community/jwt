require "../src/jwt"

payload = {"foo" => "bar", "aud" => ["sergey", "julia"]}
token = JWT.encode(payload, "key", JWT::Algorithm::HS256)

# OK, aud matches
payload, header = JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "sergey")

# aud does not match, raises JWT::InvalidAudienceError
payload, header = JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "max")
