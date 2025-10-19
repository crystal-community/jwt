require "openssl_ext"

module JWT
  class JWKS
    # JWK (JSON Web Key) structure
    struct JWK
      include JSON::Serializable
      include JSON::Serializable::Unmapped

      # Key ID
      property kid : String

      # Key Type (RSA, EC, etc.)
      property kty : String

      # Public key use (sig, enc)
      property use : String?

      # Algorithm (RS256, ES256, etc.)
      property alg : String?

      # RSA public key modulus
      property n : String?

      # RSA public key exponent
      property e : String?

      # EC curve (P-256, P-384, P-521)
      property crv : String?

      # EC x coordinate
      property x : String?

      # EC y coordinate
      property y : String?

      # X.509 certificate SHA-1 thumbprint
      property x5t : String?

      # X.509 certificate SHA-256 thumbprint
      @[JSON::Field(key: "x5t#S256")]
      property x5t_s256 : String?

      # OKP key parameter (Ed25519 public key)
      property? d : String?

      # Key operations
      property key_ops : Array(String)?

      # Convert JWK to PEM format
      def to_pem : String
        case kty
        when "RSA"
          jwk_rsa_to_pem
        when "EC"
          jwk_ec_to_pem
        when "OKP"
          jwk_okp_to_pem
        else
          raise UnsupportedAlgorithmError.new("Unsupported key type: #{kty}")
        end
      end

      private def jwk_rsa_to_pem : String
        n_val = self.n
        e_val = self.e
        raise DecodeError.new("Missing RSA key components (n, e)") unless n_val && e_val

        modulus = OpenSSL::BN.from_bin(Base64.decode(n_val))
        exponent = OpenSSL::BN.from_bin(Base64.decode(e_val))

        rsa = LibCrypto.rsa_new
        LibCrypto.rsa_set0_key(rsa, modulus, exponent, nil)

        io = IO::Memory.new
        bio = OpenSSL::GETS_BIO.new(io)
        LibCrypto.pem_write_bio_rsa_pub_key(bio, rsa)

        io.to_s
      end

      private def jwk_ec_to_pem : String
        crv_val = self.crv
        x_val = self.x
        y_val = self.y
        raise DecodeError.new("Missing EC key components (crv, x, y)") unless crv_val && x_val && y_val

        # Map JWK curve names to OpenSSL curve names
        curve_name = case crv_val
                     when "P-256"
                       "prime256v1"
                     when "P-384"
                       "secp384r1"
                     when "P-521"
                       "secp521r1"
                     when "secp256k1"
                       "secp256k1"
                     else
                       raise UnsupportedAlgorithmError.new("Unsupported EC curve: #{crv_val}")
                     end

        # Decode x and y coordinates
        x_bytes = Base64.decode(x_val)
        y_bytes = Base64.decode(y_val)

        # Create uncompressed point format (0x04 || x || y)
        point_bytes = Bytes.new(1 + x_bytes.size + y_bytes.size)
        point_bytes[0] = 0x04_u8
        x_bytes.copy_to(point_bytes + 1)
        y_bytes.copy_to(point_bytes + 1 + x_bytes.size)

        # Build DER encoding of SubjectPublicKeyInfo (RFC 5480)
        der = build_ec_public_key_der(curve_name, point_bytes)
        pem_encode_public_key(der)
      end

      private def build_ec_public_key_der(curve_name : String, point : Bytes) : Bytes
        # SubjectPublicKeyInfo ::= SEQUENCE {
        #   algorithm AlgorithmIdentifier,
        #   subjectPublicKey BIT STRING
        # }
        #
        # AlgorithmIdentifier ::= SEQUENCE {
        #   algorithm OBJECT IDENTIFIER (id-ecPublicKey),
        #   parameters ECParameters (namedCurve OBJECT IDENTIFIER)
        # }

        # OID for id-ecPublicKey (1.2.840.10045.2.1)
        ec_public_key_oid = Bytes[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]

        # OID for the curve
        curve_oid = case curve_name
                    when "prime256v1" # P-256 (1.2.840.10045.3.1.7)
                      Bytes[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                    when "secp384r1" # P-384 (1.3.132.0.34)
                      Bytes[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
                    when "secp521r1" # P-521 (1.3.132.0.35)
                      Bytes[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]
                    when "secp256k1" # secp256k1 (1.3.132.0.10)
                      Bytes[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]
                    else
                      raise UnsupportedAlgorithmError.new("Unknown curve: #{curve_name}")
                    end

        # Build AlgorithmIdentifier SEQUENCE
        alg_id_content = Bytes.new(ec_public_key_oid.size + curve_oid.size)
        ec_public_key_oid.copy_to(alg_id_content)
        curve_oid.copy_to(alg_id_content + ec_public_key_oid.size)
        alg_id = encode_der_sequence(alg_id_content)

        # Build BIT STRING for public key (point)
        # BIT STRING has a leading byte for unused bits (0x00)
        bit_string_content = Bytes.new(1 + point.size)
        bit_string_content[0] = 0x00_u8
        point.copy_to(bit_string_content + 1)
        bit_string = encode_der_bitstring(bit_string_content)

        # Build SubjectPublicKeyInfo SEQUENCE
        spki_content = Bytes.new(alg_id.size + bit_string.size)
        alg_id.copy_to(spki_content)
        bit_string.copy_to(spki_content + alg_id.size)
        encode_der_sequence(spki_content)
      end

      private def encode_der_sequence(content : Bytes) : Bytes
        encode_der_tlv(0x30, content)
      end

      private def encode_der_bitstring(content : Bytes) : Bytes
        encode_der_tlv(0x03, content)
      end

      private def encode_der_tlv(tag : UInt8, content : Bytes) : Bytes
        # Encode TLV (Tag-Length-Value)
        length = content.size

        if length < 128
          # Short form
          result = Bytes.new(1 + 1 + length)
          result[0] = tag
          result[1] = length.to_u8
          content.copy_to(result + 2)
          result
        else
          # Long form
          length_bytes = encode_length_long_form(length)
          result = Bytes.new(1 + length_bytes.size + length)
          result[0] = tag
          length_bytes.copy_to(result + 1)
          content.copy_to(result + 1 + length_bytes.size)
          result
        end
      end

      private def encode_length_long_form(length : Int) : Bytes
        # Count how many bytes needed
        byte_count = 0
        temp = length
        while temp > 0
          byte_count += 1
          temp >>= 8
        end

        result = Bytes.new(1 + byte_count)
        result[0] = (0x80 | byte_count).to_u8

        byte_count.times do |i|
          result[byte_count - i] = (length & 0xFF).to_u8
          length >>= 8
        end

        result
      end

      private def pem_encode_public_key(der : Bytes) : String
        # Base64 encode and wrap in PEM format
        b64 = Base64.strict_encode(der)

        # Wrap to 64 characters per line
        lines = [] of String
        lines << "-----BEGIN PUBLIC KEY-----"

        offset = 0
        while offset < b64.size
          line_length = Math.min(64, b64.size - offset)
          lines << b64[offset, line_length]
          offset += line_length
        end

        lines << "-----END PUBLIC KEY-----"
        lines.join("\n") + "\n"
      end

      private def jwk_okp_to_pem : String
        crv_val = self.crv
        x_val = self.x
        raise DecodeError.new("Missing OKP key components (crv, x)") unless crv_val && x_val

        # Only Ed25519 is supported for now
        unless crv_val == "Ed25519"
          raise UnsupportedAlgorithmError.new("Unsupported OKP curve: #{crv_val}. Only Ed25519 is supported")
        end

        # For EdDSA, we return the raw key bytes as a hex string
        # The JWT library expects Ed25519 keys in this format
        x_bytes = Base64.decode(x_val)
        x_bytes.hexstring
      end
    end

    # JWKS (JSON Web Key Set) structure
    struct JWKSet
      include JSON::Serializable

      property keys : Array(JWK)
    end
  end
end
