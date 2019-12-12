require "../src/jwt"

# Create token that expires in 1 minute
exp = Time.utc.to_unix + 60
payload = {"foo" => "bar", "exp" => exp}
token = JWT.encode(payload, "SecretKey", JWT::Algorithm::HS256)

# Can be decoded
payload, header = JWT.decode(token, "SecretKey", JWT::Algorithm::HS256)

sleep 61
# Already is expired, raises JWT::ExpiredSignatureError
payload, header = JWT.decode(token, "SecretKey", JWT::Algorithm::HS256)
