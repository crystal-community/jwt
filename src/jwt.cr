require "json"
require "base64"
require "openssl/hmac"

require "./jwt/*"

module JWT
  extend self

  def encode(payload, key : String, algorithm : String) : String
    segments = [] of String
    segments << encode_header(algorithm)
    segments << encode_payload(payload)
    segments << encoded_signature(algorithm, key, segments.join("."))
    segments.join(".")
  end

  def decode(token : String, key : String, algorithm : String, **opts) : Tuple
    segments = token.split(".")

    unless segments.size == 3
      raise DecodeError.new("Not enough or too many segments in the token")
    end

    encoded_header, encoded_payload, encoded_signature = segments
    expected_encoded_signature = encoded_signature(algorithm, key, "#{encoded_header}.#{encoded_payload}")

    if encoded_signature != expected_encoded_signature
      raise VerificationError.new("Signature verification failed")
    end

    header_json = Base64.decode_string(encoded_header)
    header = JSON.parse(header_json).as_h

    payload_json = Base64.decode_string(encoded_payload)
    payload = JSON.parse(payload_json).as_h

    validate_exp!(payload["exp"]) if payload["exp"]?
    validate_nbf!(payload["nbf"]) if payload["nbf"]?
    validate_aud!(payload, opts[:aud]?) if opts[:aud]?
    validate_iss!(payload, opts[:iss]?) if opts[:iss]?
    validate_sub!(payload, opts[:sub]?) if opts[:sub]?

    {payload, header}
  rescue Base64::Error
    raise DecodeError.new("Invalid Base64")
  rescue JSON::ParseException
    raise DecodeError.new("Invalid JSON")
  end

  def encode_header(algorithm : String) : String
    header = {"typ" => "JWT", "alg" => algorithm}
    json = header.to_json
    base64_encode(json)
  end

  def encode_payload(payload) : String
    json = payload.to_json
    base64_encode(json)
  end

  def encoded_signature(algorithm : String, key : String, data : String)
    signature = sign(algorithm, key, data)
    base64_encode(signature)
  end

  def sign(algorithm : String, key : String, data : String)
    case algorithm
    when "none" then ""
    when "HS256"
      OpenSSL::HMAC.digest(:sha256, key, data)
    when "HS384"
      OpenSSL::HMAC.digest(:sha384, key, data)
    when "HS512"
      OpenSSL::HMAC.digest(:sha512, key, data)
    else raise(UnsupportedAlogrithmError.new("Unsupported algorithm: #{algorithm}"))
    end
  end

  private def base64_encode(data)
    Base64.urlsafe_encode(data).gsub /\=+/, ""
  end

  private def validate_exp!(exp)
    if exp.to_s.to_i < Time.now.to_unix
      raise ExpiredSignatureError.new("Signature is expired")
    end
  end

  private def validate_nbf!(nbf)
    if nbf.to_s.to_i > Time.now.to_unix
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
