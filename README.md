# JWT

An implementation of [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) in
Crystal programming language.


_The project is under development_

## Installation


Add this to your application's `shard.yml`:

```yaml
dependencies:
  jwt:
    github: greyblake/jwt
```


## Usage

```crystal
require "jwt"

# Create a token
payload = {"k1" => "v1", "k2" => "v2"}
token = JWT.encode(payload, "SecretKey", "HS256")
# => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"

# Decode a token
payload, header = JWT.decode(token, "SecretKey", "SH256")
# => [
        {"k1" => "v1", "k2" => "v2"},
        {"typ" => "JWT","alg" => "HS256"}
    ]
```

## Tests

```
crystal spec
```

## Contributors

- [greyblake](https://github.com/greyblake) Potapov Sergey - creator, maintainer
