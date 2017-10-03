# Crystal JWT [![Build Status](https://travis-ci.org/crystal-community/jwt.svg?branch=master)](https://travis-ci.org/crystal-community/jwt)

An implementation of [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) in Crystal programming language.

* [Crystal JWT](#crystal-jwt)
  * [Installation](#installation)
  * [Usage](#usage)
  * [Supported algorithms](#supported-algorithms)
  * [Supported reserved claim names](#supported-reserved-claim-names)
    * [Expiration time (exp)](#expiration-time-exp)
    * [Not before time (nbf)](#not-before-time-nbf)
    * [Issued At (iat)](#issued-at-iat)
    * [Audience (aud)](#audience-aud)
    * [Issuer (iss)](#issuer-iss)
    * [Subject (sub)](#subject-sub)
    * [JWT ID (jti)](#jwt-id-jti)
  * [Exceptions](#exceptions)
  * [Test](#test)
  * [Contributors](#contributors)

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  jwt:
    github: crystal-community/jwt
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
* [ ] RSA - in progress

## Supported reserved claim names
JSON Web Token defines some reserved claim names and how they should be used.
* ['exp' (Expiration Time) Claim](#expiration-time-exp)
* ['nbf' (Not Before Time) Claim](#not-before-time-nbf)
* ['iss' (Issuer) Claim](#issuer-iss)
* ['aud' (Audience) Claim](#audience-aud)
* ['jti' (JWT ID) Claim](#jwt-id-jti)
* ['iat' (Issued At) Claim](#issued-at-iat)
* ['sub' (Subject) Claim](#subject-sub)

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

### Issued At (iat)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.6):
> The "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can be used to determine the age of the JWT. Its value MUST be a number containing a NumericDate value. Use of this claim is OPTIONAL.

Example:
```crystal
payload = { "foo" => "bar", "iat" => Time.now.epoch }
token = JWT.encode(payload, "SecretKey", "HS256")
```

### Audience (aud)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.3):
> The aud (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT MUST be rejected. In the general case, the aud value is an array of case-sensitive strings, each containing a StringOrURI value. In the special case when the JWT has one audience, the aud value MAY be a single case-sensitive string containing a StringOrURI value. The interpretation of audience values is generally application specific. Use of this claim is OPTIONAL.

Example:
```crystal
payload = {"foo" => "bar", "aud" => ["sergey", "julia"]}
token = JWT.encode(payload, "key", "HS256")

# OK, aud matches
payload, header = JWT.decode(token, "key", "HS256", aud: "sergey")

# aud does not match, raises JWT::InvalidAudienceError
payload, header = JWT.decode(token, "key", "HS256", aud: "max")
```

### Issuer (iss)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.1):
> The iss (issuer) claim identifies the principal that issued the JWT. The processing of this claim is generally application specific. The iss value is a case-sensitive string containing a StringOrURI value. Use of this claim is OPTIONAL.

Example:
```crystal
payload = { "foo" => "bar", "iss" => "me"}
token = JWT.encode(payload, "SecretKey", "HS256")

# OK, because iss matches
payload, header = JWT.decode(token, "SecretKey", "HS256", iss: "me")

# iss does not match, raises JWT::InvalidIssuerError
payload, header = JWT.decode(token, "SecretKey", "HS256", iss: "you")
```

### Subject (sub)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.2):
> The sub (subject) claim identifies the principal that is the subject of the JWT. The Claims in a JWT are normally statements about the subject. The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique. The processing of this claim is generally application specific. The sub value is a case-sensitive string containing a StringOrURI value. Use of this claim is OPTIONAL.

Example:
```crystal
payload = { "nomo" => "Sergeo", "sub" => "Esperanto" }
token = JWT.encode(payload, "key", "HS256")

# Raises JWT::InvalidSubjectError, because "sub" claim does not match
JWT.decode(token, "key", "HS256", sub: "Junularo")
```

### JWT ID (jti)
From [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.7):
> The jti (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object; if the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well. The jti claim can be used to prevent the JWT from being replayed. The jti value is a case-sensitive string. Use of this claim is OPTIONAL.

Example:
```crystal
require "secure_random"

jti = SecureRandom.urlsafe_base64
payload = { "foo" => "bar", "jti" => jti }
token = JWT.encode(payload, "SecretKey", "HS256")
```


## Exceptions
* JWT::Error
  * JWT::DecodeError
    * JWT::VerificationError
    * JWT::ExpiredSignatureError
    * JWT::ImmatureSignatureError
    * JWT::InvalidAudienceError
    * JWT::InvalidIssuerError
    * JWT::InvalidSubjectError
  * UnsupportedAlogrithmError

## Test

```
crystal spec
```

## Contributors

- [greyblake](https://github.com/greyblake) Potapov Sergey - creator, maintainer
