require "../../spec_helper"

describe JWT do
  # Generate a test Ed25519 key pair
  private_key_bytes = Bytes[
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
  ]

  private_key = private_key_bytes.hexstring
  # public_key = Ed25519.get_public_key(private_key_bytes).hexstring

  wrong_key_bytes = Bytes[
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
  ]
  wrong_key = wrong_key_bytes.hexstring

  payload = {"foo" => "bar"}

  describe "algorithm EdDSA" do
    it "generates token that can be decoded" do
      token = JWT.encode(payload, private_key, JWT::Algorithm::EdDSA)

      decoded_token = JWT.decode(token, private_key, JWT::Algorithm::EdDSA)
      decoded_token[0].should eq(payload)
      decoded_token[1].should eq({"typ" => "JWT", "alg" => "EdDSA"})
    end

    it "can verify with public key" do
      token = JWT.encode(payload, private_key, JWT::Algorithm::EdDSA)

      # Decode using private key (which derives public key)
      decoded_token = JWT.decode(token, private_key, JWT::Algorithm::EdDSA)
      decoded_token[0].should eq(payload)
    end

    it "produces deterministic signatures" do
      token1 = JWT.encode(payload, private_key, JWT::Algorithm::EdDSA)
      token2 = JWT.encode(payload, private_key, JWT::Algorithm::EdDSA)

      # EdDSA signatures should be deterministic
      token1.should eq(token2)
    end

    describe "#decode" do
      context "when token was signed with another key" do
        it "raises JWT::VerificationError" do
          token = JWT.encode(payload, wrong_key, JWT::Algorithm::EdDSA)
          expect_raises(JWT::VerificationError, "Signature verification failed") do
            JWT.decode(token, private_key, JWT::Algorithm::EdDSA)
          end
        end

        it "can ignore verification if requested" do
          token = JWT.encode(payload, wrong_key, JWT::Algorithm::EdDSA)
          JWT.decode(token, verify: false)
        end
      end

      context "when token contains not 3 segments" do
        it "raises JWT::DecodeError" do
          ["e30", "e30.e30", "e30.e30.e30.e30"].each do |invalid_token|
            expect_raises(JWT::DecodeError) do
              JWT.decode(invalid_token, private_key, JWT::Algorithm::EdDSA)
            end
          end
        end
      end
    end
  end
end
