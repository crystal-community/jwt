require "../src/jwt"

# Encoding
payload = { "foo" => "bar" }
token = JWT.encode(payload, "SecretKey", "HS256")
pp token

# Decoding
payload, header = JWT.decode(token, "SecretKey", "HS256")
pp payload
pp header
