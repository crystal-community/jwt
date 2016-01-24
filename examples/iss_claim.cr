require "../src/jwt"

payload = { "foo" => "bar", "iss" => "me"}
token = JWT.encode(payload, "SecretKey", "HS256")

# OK, because iss matches
payload, header = JWT.decode(token, "SecretKey", "HS256", {iss: "me"})

# iss does not match, raises JWT::InvalidIssuerError
payload, header = JWT.decode(token, "SecretKey", "HS256", {iss: "you"})

