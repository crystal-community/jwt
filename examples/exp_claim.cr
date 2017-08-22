require "../src/jwt"

# Create token that expires in 1 minute
exp = Time.now.epoch + 60
payload = {"foo" => "bar", "exp" => exp}
token = JWT.encode(payload, "SecretKey", "HS256")

# Can be decoded
payload, header = JWT.decode(token, "SecretKey", "HS256")

sleep 61
# Already is expired, raises JWT::ExpiredSignatureError
payload, header = JWT.decode(token, "SecretKey", "HS256")
