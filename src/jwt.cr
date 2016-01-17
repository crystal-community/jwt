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
    case algorithm
    when "none" then ""
    when "HS256"
      signature = OpenSSL::HMAC.digest(:sha256, key, data)
      Base64.urlsafe_encode(signature)
    when "HS386"
      signature = OpenSSL::HMAC.digest(:sha386, key, data)
      Base64.urlsafe_encode(signature)
    when "HS512"
      signature = OpenSSL::HMAC.digest(:sha512, key, data)
      Base64.urlsafe_encode(signature)
    else fail("Not implemented algorithm: #{algorithm}")
    end
  end


  # TODO: verify signature and expiration time
  def decode(token : String, key : String, algorithm : String)
    encoded_header, encoded_payload, encoded_signature = token.split(".", 3)


    header_json = base64_decode(encoded_header)
    header = JSON.parse(header_json).as_h

    payload_json = base64_decode(encoded_payload)
    payload = JSON.parse(payload_json).as_h

    signature = base64_decode(encoded_signature)

    [payload, header]
  end

  def base64_decode(str : String)
    Base64.decode_string(str)
  end
end
