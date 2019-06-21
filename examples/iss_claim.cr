require "../src/jwt"

payload = {"foo" => "bar", "iss" => "me"}
token = JWT.encode(payload, "SecretKey", JWT::Algorithm::HS256)

# OK, because iss matches
payload, header = JWT.decode(token, "SecretKey", JWT::Algorithm::HS256, iss: "me")

# iss does not match, raises JWT::InvalidIssuerError
payload, header = JWT.decode(token, "SecretKey", JWT::Algorithm::HS256, iss: "you")
