# Crystal JWT [![Build Status](https://travis-ci.org/greyblake/crystal-jwt.svg?branch=master)](https://travis-ci.org/greyblake/crystal-jwt)

An implementation of [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) in Crystal programming language.

* [Crystal JWT](#crystal-jwt)
  * [Installation](#installation)
  * [Usage](#usage)
  * [Supported algorithms](#supported-algorithms)
  * [Supported reserved claim names](#supported-reserved-claim-names)
    * [Expiration time (exp)](#expiration-time-exp)
    * [Not before time (nbf)](#not-before-time-nbf)
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
JSON Web Token defines some reserved claim names and how they should be used. Currently the library supports the following:
* [x] 'exp' (Expiration Time) Claim
* [x] 'nbf' (Not Before Time) Claim
* [ ] 'iss' (Issuer) Claim
* [ ] 'aud' (Audience) Claim
* [ ] 'jti' (JWT ID) Claim
* [ ] 'iat' (Issued At) Claim
* [ ] 'sub' (Subject) Claim

### Expiration Time (exp)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.4):
> The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. The processing of the "exp" claim requires that the current date/time MUST be before the expiration date/time listed in the "exp" claim.
> Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.  Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL

Example:

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

### Not Before Time (nbf)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.5):
> MUST NOT be accepted for processing. The processing of the "nbf" The "nbf" (not before) claim identifies the time before which the JWT claim requires that the current date/time MUST be after or equal to the not-before date/time listed in the "nbf" claim.
> Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.  Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.

Example:

```crystal
# Create token that will become acceptable in 1 minute
nbf = Time.now.epoch + 60
payload = { "foo" => "bar", "nbf" => nbf }
token = JWT.encode(payload, "SecretKey", "HS256")

# Currently it's not acceptable, raises JWT::ImmatureSignatureError
JWT.decode(token, "SecretKey", "HS256")
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
