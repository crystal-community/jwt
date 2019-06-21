require "../src/jwt"
require "secure_random"

jti = SecureRandom.urlsafe_base64
payload = {"foo" => "bar", "jti" => jti}
token = JWT.encode(payload, "SecretKey", JWT::Algorithm::HS256)
pp token
