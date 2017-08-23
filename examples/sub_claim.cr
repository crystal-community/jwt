require "../src/jwt"

payload = {"nomo" => "Sergeo", "sub" => "Esperanto"}
token = JWT.encode(payload, "key", "HS256")

# Raises JWT::InvalidSubjectError, because "sub" claim does not match
JWT.decode(token, "key", "HS256", sub: "Junularo")
