require "../src/jwt"

payload = {"nomo" => "Sergeo", "sub" => "Esperanto"}
token = JWT.encode(payload, "key", JWT::Algorithm::HS256)

# Raises JWT::InvalidSubjectError, because "sub" claim does not match
JWT.decode(token, "key", JWT::Algorithm::HS256, sub: "Junularo")
