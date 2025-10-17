require "../../spec_helper"

describe JWT do
  # Generate secp256k1 key (Bitcoin/Ethereum curve)
  ec_key = OpenSSL::PKey::EC.generate_by_curve_name("secp256k1")
  private_key = ec_key.to_pem
  public_key = ec_key.public_key.to_pem

  wrong_key = OpenSSL::PKey::EC.generate_by_curve_name("secp256k1").to_pem
  payload = {"foo" => "bar"}

  describe "algorithm ES256K" do
    it "generates token that can be decoded" do
      token = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)

      decoded_token = JWT.decode(token, public_key, JWT::Algorithm::ES256K)
      decoded_token[0].should eq(payload)
      decoded_token[1].should eq({"typ" => "JWT", "alg" => "ES256K"})

      decoded_token = JWT.decode(token, private_key, JWT::Algorithm::ES256K)
      decoded_token[0].should eq(payload)
      decoded_token[1].should eq({"typ" => "JWT", "alg" => "ES256K"})
    end

    it "uses secp256k1 curve (Bitcoin/Ethereum curve)" do
      token = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)
      decoded_token = JWT.decode(token, public_key, JWT::Algorithm::ES256K)
      decoded_token[0].should eq(payload)
    end

    it "signature size is 64 bytes (32 bytes for r, 32 bytes for s)" do
      token = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)
      # JWT format: header.payload.signature
      parts = token.split('.')
      signature = Base64.decode(parts[2])
      # secp256k1 with SHA-256 produces 64-byte signature (32 bytes r + 32 bytes s)
      signature.size.should eq(64)
    end

    it "can encode and decode with different instances" do
      token1 = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)
      token2 = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)

      # ECDSA signatures include randomness, so tokens should be different
      token1.should_not eq(token2)

      # But both should decode successfully
      JWT.decode(token1, public_key, JWT::Algorithm::ES256K)[0].should eq(payload)
      JWT.decode(token2, public_key, JWT::Algorithm::ES256K)[0].should eq(payload)
    end

    describe "#decode" do
      context "when token was signed with another key" do
        it "raises JWT::VerificationError" do
          token = JWT.encode(payload, wrong_key, JWT::Algorithm::ES256K)
          expect_raises(JWT::VerificationError, "Signature verification failed") do
            JWT.decode(token, public_key, JWT::Algorithm::ES256K)
          end
        end

        it "can ignore verification if requested" do
          token = JWT.encode(payload, wrong_key, JWT::Algorithm::ES256K)
          JWT.decode(token, verify: false)
        end
      end

      context "when token contains not 3 segments" do
        it "raises JWT::DecodeError" do
          ["e30", "e30.e30", "e30.e30.e30.e30"].each do |invalid_token|
            expect_raises(JWT::DecodeError) do
              JWT.decode(invalid_token, public_key, JWT::Algorithm::ES256K)
            end
          end
        end
      end
    end

    describe "blockchain/cryptocurrency compatibility" do
      it "ES256K uses the same curve as Bitcoin and Ethereum" do
        # secp256k1 is the elliptic curve used by Bitcoin and Ethereum
        # This makes ES256K JWTs compatible with blockchain ecosystems
        token = JWT.encode({"chain" => "bitcoin", "address" => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}, private_key, JWT::Algorithm::ES256K)
        decoded = JWT.decode(token, public_key, JWT::Algorithm::ES256K)
        decoded[0]["chain"].should eq("bitcoin")
        decoded[0]["address"].should eq("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
      end
    end
  end
end
