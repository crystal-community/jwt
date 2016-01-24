# Crystal JWT

An implementation of [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) in Crystal programming language.

* [Crystal JWT](#crystal-jwt)
  * [Installation](#installation)
  * [Usage](#usage)
  * [Supported algorithms](#supported-algorithms)
  * [Supported reserved claim names](#supported-reserved-claim-names)
    * [Expiration time example](#expiration-time-example)
  * [Exceptions](#exceptions)
  * [Test](#test)
  * [Contributors](#contributors)

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  jwt:
    github: greyblake/crystal-jwt
```


## Usage

```crystal
# Encoding
payload = { "foo" => "bar" }
token = JWT.encode(payload, "SecretKey", "HS256")
# => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.Y3shN5Wh4FmOPM34biIm9QQmat373hJFKNxgSANQWJo"

# Decoding
payload, header = JWT.decode(token, "$secretKey", "HS256")
# payload = {"foo" => "bar"}
# header = {"typ" => "JWT", "alg" => "HS256"}
```

## Supported algorithms
* [x] none
* [x] HMAC (HS256, HS384, HS512)
* [ ] RSA - will be implemented as soon, as Crystal has RSA support in the standard library.

## Supported reserved claim names
JSON Web Token defines some reserved claim names and how they should be used. Currently the library supports some of them:
* [x] 'exp' (Expiration Time) Claim
* [ ] 'nbf' (Not Before Time) Claim
* [ ] 'iss' (Issuer) Claim
* [ ] 'aud' (Audience) Claim
* [ ] 'jti' (JWT ID) Claim
* [ ] 'iat' (Issued At) Claim
* [ ] 'sub' (Subject) Claim

### Expiration time example
```crystal
# Create token that expires in 1 minute
exp = Time.now.epoch + 60
payload = { "foo" => "bar", "exp" => exp }
token = JWT.encode(payload, "SecretKey", "HS256")

# At this moment token can be decoded
payload, header = JWT.decode(token, "SecretKey", "HS256")

sleep 61
# Now token is expired, so JWT::ExpiredSignatureError will be raised
payload, header = JWT.decode(token, "SecretKey", "HS256")
```

## Exceptions
* JWT::Error
  * JWT::DecodeError
    * JWT::VerificationError
    * JWT::ExpiredSignatureError
  * UnsupportedAlogrithmError

## Test

```
crystal spec
```

## Contributors

- [greyblake](https://github.com/greyblake) Potapov Sergey - creator, maintainer
