require "json"
require "base64"
require "openssl/hmac"

require "./jwt/*"

module JWT
  extend self

  # Basic JWT exception.
  class Error < ::Exception; end;

  # Is raised on attempt to use unsupported algorithm.
  class UnsupportedAlogrithmError < Error; end;

  # raised when failed to decode token
  class DecodeError < Error; end;

  # Is raised when failed to verify signature.
  class VerificationError < DecodeError; end;

  # Is raised when signature is expired (see `exp` reserved claim name)
  class ExpiredSignatureError < DecodeError; end;

  def encode(payload, key : String, algorithm : String) : String
    segments = [] of String
    segments << encode_header(algorithm)
    segments << encode_payload(payload)
    segments << encoded_signature(algorithm, key, segments.join("."))
    segments.join(".")
  end

  def decode(token : String, key : String, algorithm : String)
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

    if payload["exp"]? && payload["exp"].to_s.to_i < Time.now.epoch
      raise ExpiredSignatureError.new("Signature is expired")
    end

    [payload, header]
  rescue Base64::Error
    raise DecodeError.new("Invalid Base64")
  rescue JSON::ParseException
    raise DecodeError.new("Invalid JSON")
  end

  def encode_header(algorithm : String) : String
    header = { "typ" => "JWT", "alg" => algorithm }
    json = header.to_json
    Base64.urlsafe_encode(json)
  end

  def encode_payload(payload) : String
    json = payload.to_json
    Base64.urlsafe_encode(json)
  end

  def encoded_signature(algorithm : String, key : String, data : String)
    signature = sign(algorithm, key, data)
    Base64.urlsafe_encode(signature)
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
end
