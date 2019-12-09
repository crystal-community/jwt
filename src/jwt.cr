require "json"
require "base64"
require "openssl/hmac"
require "openssl_ext"

require "./jwt/*"

module JWT
  extend self

  enum Algorithm
    None
    HS256
    HS384
    HS512
    RS256
    RS384
    RS512
    ES256
    ES384
    ES512
  end

  def encode(payload, key : String, algorithm : Algorithm, **header_keys) : String
    segments = [] of String
    segments << encode_header(algorithm, **header_keys)
    segments << encode_payload(payload)
    segments << encoded_signature(algorithm, key, segments.join("."))
    segments.join(".")
  end

  def decode(token : String, key : String = "", algorithm : Algorithm = Algorithm::None, verify = true, validate = true, **opts) : Tuple
    verify_data, _, encoded_signature = token.rpartition('.')

    count = verify_data.count('.')
    if count != 1
      raise DecodeError.new("Invalid number of segments in the token. Expected 3 got #{count + 2}")
    end

    if verify
      # public key verification for RSA and ECDSA algorithms
      case algorithm
      when Algorithm::RS256, Algorithm::RS384, Algorithm::RS512
        rsa = OpenSSL::PKey::RSA.new(key)
        digest = OpenSSL::Digest.new("sha#{algorithm.to_s[2..-1]}")
        if !rsa.verify(digest, Base64.decode_string(encoded_signature), verify_data)
          raise VerificationError.new("Signature verification failed")
        end
      when Algorithm::ES256, Algorithm::ES384, Algorithm::ES512
        dsa = OpenSSL::PKey::EC.new(key)
        digest = OpenSSL::Digest.new("sha#{algorithm.to_s[2..-1]}").update(verify_data).digest
        if !dsa.ec_verify(digest, Base64.decode_string(encoded_signature))
          raise VerificationError.new("Signature verification failed")
        end
      else
        expected_encoded_signature = encoded_signature(algorithm, key, verify_data)
        if encoded_signature != expected_encoded_signature
          raise VerificationError.new("Signature verification failed")
        end
      end
    end

    encoded_header, encoded_payload = verify_data.split('.')
    header_json = Base64.decode_string(encoded_header)
    header = JSON.parse(header_json).as_h

    payload_json = Base64.decode_string(encoded_payload)
    payload = JSON.parse(payload_json).as_h

    if validate
      validate_exp!(payload["exp"]) if payload["exp"]?
      validate_nbf!(payload["nbf"]) if payload["nbf"]?
      validate_aud!(payload, opts[:aud]?) if opts[:aud]?
      validate_iss!(payload, opts[:iss]?) if opts[:iss]?
      validate_sub!(payload, opts[:sub]?) if opts[:sub]?
    end

    {payload, header}
  rescue Base64::Error
    raise DecodeError.new("Invalid Base64")
  rescue JSON::ParseException
    raise DecodeError.new("Invalid JSON")
  end

  def encode_header(algorithm : Algorithm, **keys) : String
    alg = algorithm == Algorithm::None ? "none" : algorithm.to_s
    header = {typ: "JWT", alg: alg}.merge(keys)
    base64_encode(header.to_json)
  end

  def encode_payload(payload) : String
    json = payload.to_json
    base64_encode(json)
  end

  def encoded_signature(algorithm : Algorithm, key : String, data : String)
    signature = sign(algorithm, key, data)
    base64_encode(signature)
  end

  def sign(algorithm : Algorithm, key : String, data : String)
    case algorithm
    when Algorithm::None then ""
    when Algorithm::HS256
      OpenSSL::HMAC.digest(:sha256, key, data)
    when Algorithm::HS384
      OpenSSL::HMAC.digest(:sha384, key, data)
    when Algorithm::HS512
      OpenSSL::HMAC.digest(:sha512, key, data)
    when Algorithm::RS256
      OpenSSL::PKey::RSA.new(key).sign(OpenSSL::Digest.new("sha256"), data)
    when Algorithm::RS384
      OpenSSL::PKey::RSA.new(key).sign(OpenSSL::Digest.new("sha384"), data)
    when Algorithm::RS512
      OpenSSL::PKey::RSA.new(key).sign(OpenSSL::Digest.new("sha512"), data)
    when Algorithm::ES256
      OpenSSL::PKey::EC.new(key).ec_sign(OpenSSL::Digest.new("sha256").update(data).digest)
    when Algorithm::ES384
      OpenSSL::PKey::EC.new(key).ec_sign(OpenSSL::Digest.new("sha384").update(data).digest)
    when Algorithm::ES512
      OpenSSL::PKey::EC.new(key).ec_sign(OpenSSL::Digest.new("sha512").update(data).digest)
    else
      raise(UnsupportedAlgorithmError.new("Unsupported algorithm: #{algorithm}"))
    end
  end

  private def base64_encode(data)
    Base64.urlsafe_encode(data).gsub /\=+/, ""
  end

  private def validate_exp!(exp)
    if exp.to_s.to_i < Time.utc.to_unix
      raise ExpiredSignatureError.new("Signature is expired")
    end
  end

  private def validate_nbf!(nbf)
    if nbf.to_s.to_i > Time.utc.to_unix
      raise ImmatureSignatureError.new("Signature nbf has not been reached")
    end
  end

  private def validate_aud!(payload, aud)
    if !payload["aud"]?
      raise InvalidAudienceError.new("Invalid audience (aud). Expected #{aud.inspect}, received nothing")
    elsif payload["aud"].as_s?
      if aud != payload["aud"].as_s
        raise InvalidAudienceError.new("Invalid audience (aud). Expected #{aud.inspect}, received #{payload["aud"].inspect}")
      end
    elsif payload["aud"].as_a?
      auds = payload["aud"].as_a
      if !auds.includes?(aud)
        msg = "Invalid audience (aud). Expected #{aud.inspect}, received #{payload["aud"].inspect}"
        raise InvalidAudienceError.new(msg)
      end
    else
      raise InvalidAudienceError.new("aud claim must be a string or array of strings")
    end
  end

  private def validate_iss!(payload, iss)
    if !payload["iss"]?
      raise InvalidIssuerError.new("Invalid issuer (iss). Expected #{iss.inspect}, received nothing")
    elsif payload["iss"] != iss
      raise InvalidIssuerError.new("Invalid issuer (iss). Expected #{iss.inspect}, received #{payload["iss"].inspect}")
    end
  end

  private def validate_sub!(payload, sub)
    if payload["sub"]?
      if payload["sub"] != sub
        raise InvalidSubjectError.new("Invalid subject (sub). Expected #{sub.inspect}, received #{payload["sub"].inspect}")
      end
    else
      raise InvalidSubjectError.new("Invalid subject (sub). Expected #{sub.inspect}, received nothing")
    end
  end
end
