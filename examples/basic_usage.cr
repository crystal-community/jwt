require "../src/jwt"

# Encoding
payload = {"foo" => "bar"}
token = JWT.encode(payload, "SecretKey", "HS256")
pp token

# Decoding
payload, header = JWT.decode(token, "SecretKey", "HS256")
pp payload
pp header

# exp field in ms
payload, header = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1aWQiOiI4MjY4OTEwOSIsImlhdCI6MTUwMzM5NDAwNjI1NSwicGF5bG9hZCI6eyJyb2xlIjoiRWxldmUiLCJlbWFpbCI6ImVsZXZlMUBlc3NhaS5jb20iLCJ1c2VybmFtZSI6IlAuQkFSUkVTIn0sImV4cCI6MTUwMzM5NzYwNjI1OH0.FcfRg1JYqIT9ZQQneEDRbt16_ltN6dyAfuFezsN0uBJ8jO-jAPzUYqlRJ77hKvjF2h51jvdtII5GVoEw72TIyw", "fJShJ9ZH0c05eXZNzi0qcBV3WeLar2Vi9zIdo8Ggbk3LoLTpkzTef8L0AYlwzcO1YotNsaBydIYk50F2", "HS512")
pp payload
pp header
