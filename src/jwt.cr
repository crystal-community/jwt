require "json"
require "base64"
require "bindata/asn1"
require "openssl/hmac"
require "openssl_ext"
require "crypto/subtle"

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

  def decode(token : String, key : String = "", algorithm : Algorithm = Algorithm::None, verify = true, validate = true, **options) : Tuple
    verify_data, _, encoded_signature = token.rpartition('.')

    check_verify_data(verify_data)

    verify(key, algorithm, verify_data, encoded_signature) if verify

    header, payload = decode_verify_data(verify_data)
    validate(payload, options) if validate

    {payload, header}
  rescue error : TypeCastError
    raise DecodeError.new("Invalid JWT payload", error)
  end

  def decode(token : String, algorithm : Algorithm? = nil, verify = true, validate = true, **options, &block) : Tuple
    verify_data, _, encoded_signature = token.rpartition('.')

    check_verify_data(verify_data)
    header, payload = decode_verify_data(verify_data)

    if algorithm.nil?
      begin
        algorithm = Algorithm.parse header["alg"].as_s
      rescue error : ArgumentError | KeyError
        raise DecodeError.new("Invalid alg in JWT header", error)
      end
    end
    key = yield header, payload

    verify(key.not_nil!, algorithm.not_nil!, verify_data, encoded_signature) if verify
    validate(payload, options) if validate

    {payload, header}
  rescue error : TypeCastError
    raise DecodeError.new("Invalid JWT payload", error)
  end

  private def check_verify_data(verify_data)
    count = verify_data.count('.')
    if count != 1
      raise DecodeError.new("Invalid number of segments in the token. Expected 3 got #{count + 2}")
    end
  end

  private def decode_verify_data(verify_data)
    encoded_header, encoded_payload = verify_data.split('.')
    header_json = Base64.decode_string(encoded_header)
    header = JSON.parse(header_json).as_h

    payload_json = Base64.decode_string(encoded_payload)
    payload = JSON.parse(payload_json)

    {header, payload}
  rescue error : Base64::Error
    raise DecodeError.new("Invalid Base64", error)
  rescue error : JSON::ParseException
    raise DecodeError.new("Invalid JSON", error)
  rescue error : TypeCastError
    raise DecodeError.new("Invalid JWT header", error)
  end

  # public key verification for RSA and ECDSA algorithms
  private def verify(key, algorithm, verify_data, encoded_signature)
    case algorithm
    in Algorithm::RS256, Algorithm::RS384, Algorithm::RS512
      rsa = OpenSSL::PKey::RSA.new(key)
      digest = OpenSSL::Digest.new("sha#{algorithm.to_s[2..-1]}")
      if !rsa.verify(digest, Base64.decode_string(encoded_signature), verify_data)
        raise VerificationError.new("Signature verification failed")
      end
    in Algorithm::ES256, Algorithm::ES384, Algorithm::ES512
      dsa = OpenSSL::PKey::EC.new(key)
      digest = OpenSSL::Digest.new("sha#{algorithm.to_s[2..-1]}").update(verify_data).final
      result = begin
        dsa.ec_verify(digest, raw_to_asn1(Base64.decode(encoded_signature), dsa))
      rescue e
        raise VerificationError.new("Signature verification failed", e)
      end
      raise VerificationError.new("Signature verification failed") if !result
    in Algorithm::HS256, Algorithm::HS384, Algorithm::HS512, Algorithm::None
      expected_encoded_signature = encoded_signature(algorithm, key, verify_data)
      unless Crypto::Subtle.constant_time_compare(encoded_signature, expected_encoded_signature)
        raise VerificationError.new("Signature verification failed")
      end
    end
  end

  private def validate(payload, opts)
    check = payload.as_h
    validate_exp!(check["exp"]) if check["exp"]?
    validate_nbf!(check["nbf"]) if check["nbf"]?
    validate_aud!(check, opts[:aud]?) if opts[:aud]?
    validate_iss!(check, opts[:iss]?) if opts[:iss]?
    validate_sub!(check, opts[:sub]?) if opts[:sub]?
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

  # ameba:disable Metrics/CyclomaticComplexity
  def sign(algorithm : Algorithm, key : String, data : String)
    case algorithm
    in Algorithm::None then ""
    in Algorithm::HS256
      OpenSSL::HMAC.digest(:sha256, key, data)
    in Algorithm::HS384
      OpenSSL::HMAC.digest(:sha384, key, data)
    in Algorithm::HS512
      OpenSSL::HMAC.digest(:sha512, key, data)
    in Algorithm::RS256
      OpenSSL::PKey::RSA.new(key).sign(OpenSSL::Digest.new("sha256"), data)
    in Algorithm::RS384
      OpenSSL::PKey::RSA.new(key).sign(OpenSSL::Digest.new("sha384"), data)
    in Algorithm::RS512
      OpenSSL::PKey::RSA.new(key).sign(OpenSSL::Digest.new("sha512"), data)
    in Algorithm::ES256
      pkey = OpenSSL::PKey::EC.new(key)
      asn1_to_raw(pkey.ec_sign(OpenSSL::Digest.new("sha256").update(data).final), pkey)
    in Algorithm::ES384
      pkey = OpenSSL::PKey::EC.new(key)
      asn1_to_raw(pkey.ec_sign(OpenSSL::Digest.new("sha384").update(data).final), pkey)
    in Algorithm::ES512
      # https://tools.ietf.org/html/rfc7518#section-3.4
      # NOTE:: key size 521 for ES512
      pkey = OpenSSL::PKey::EC.new(key)
      asn1_to_raw(pkey.ec_sign(OpenSSL::Digest.new("sha512").update(data).final), pkey)
    end
  end

  private def base64_encode(data)
    Base64.urlsafe_encode(data, false)
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
      unless Crypto::Subtle.constant_time_compare(aud.to_s, payload["aud"].as_s)
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
    elsif !Crypto::Subtle.constant_time_compare(iss.to_s, payload["iss"].to_s)
      raise InvalidIssuerError.new("Invalid issuer (iss). Expected #{iss.inspect}, received #{payload["iss"].inspect}")
    end
  end

  private def validate_sub!(payload, sub)
    if payload["sub"]?
      unless Crypto::Subtle.constant_time_compare(sub.to_s, payload["sub"].to_s)
        raise InvalidSubjectError.new("Invalid subject (sub). Expected #{sub.inspect}, received #{payload["sub"].inspect}")
      end
    else
      raise InvalidSubjectError.new("Invalid subject (sub). Expected #{sub.inspect}, received nothing")
    end
  end

  # OpenSSL returns signatures encoded as ASN.1 values
  # However the JWT specification requires these to be raw integers
  def asn1_to_raw(signature : Bytes, private_key : OpenSSL::PKey::EC) : Bytes
    byte_size = (private_key.group_degree + 7) // 8
    io = IO::Memory.new(signature)
    sequence = io.read_bytes(ASN1::BER)
    parts = sequence.children
    bytes = parts[0].get_integer_bytes
    char = parts[1].get_integer_bytes

    raw = IO::Memory.new

    size = byte_size - bytes.size
    raw.write Bytes.new(size) if size > 0
    raw.write bytes

    size = byte_size - char.size
    raw.write Bytes.new(size) if size > 0
    raw.write char
    raw.to_slice
  end

  def raw_to_asn1(signature : Bytes, public_key : OpenSSL::PKey::EC) : Bytes
    byte_size = (public_key.group_degree + 7) // 8
    sig_bytes = signature[0..(byte_size - 1)]
    sig_char = signature[byte_size..-1]

    bytes_asn1 = ASN1::BER.new
    bytes_asn1.tag_number = ASN1::BER::UniversalTags::Integer
    bytes_asn1.set_integer sig_bytes

    char_asn1 = ASN1::BER.new
    char_asn1.tag_number = ASN1::BER::UniversalTags::Integer
    char_asn1.set_integer sig_char

    sequence = ASN1::BER.new
    sequence.tag_number = ASN1::BER::UniversalTags::Sequence
    sequence.children = {bytes_asn1, char_asn1}
    sequence.to_slice
  end
end
