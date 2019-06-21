require "../src/jwt"

# Encoding
payload = {"foo" => "bar"}
token = JWT.encode(payload, "SecretKey", JWT::Algorithm::HS256)
pp token

# Decoding
payload, header = JWT.decode(token, "SecretKey", JWT::Algorithm::HS256)
pp payload
pp header
