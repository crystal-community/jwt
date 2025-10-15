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

      # Convert JWK to PEM format
      def to_pem : String
        case kty
        when "RSA"
          jwk_rsa_to_pem
        when "EC"
          # EC keys are not yet fully supported
          # Main use case (Azure AD/Entra) uses RS256 (RSA keys)
          raise UnsupportedAlgorithmError.new("EC key type not yet fully supported. Please use RSA keys (RS256/RS384/RS512)")
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
    end

    # JWKS (JSON Web Key Set) structure
    struct JWKSet
      include JSON::Serializable

      property keys : Array(JWK)
    end
  end
end
