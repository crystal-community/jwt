require "../../spec_helper"

describe JWT do
  private_key256 = "-----BEGIN EC PRIVATE KEY-----\n" +
                   "MHcCAQEEICQ13objo8V5wNl7ioToptpI6nJ2fvNcy+fgWQ2BrzgnoAoGCCqGSM49\n" +
                   "AwEHoUQDQgAEUeAfjUi57m5PZ7UEiaBLUzex/Jsq0l+dC5XixCUe01qqZJ3vFe7e\n" +
                   "zVdalVZaibmLJQ2VUgPRTrlT2yv462U6xg==\n" +
                   "-----END EC PRIVATE KEY-----\n"

  public_key256 = "-----BEGIN PUBLIC KEY-----\n" +
                  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUeAfjUi57m5PZ7UEiaBLUzex/Jsq\n" +
                  "0l+dC5XixCUe01qqZJ3vFe7ezVdalVZaibmLJQ2VUgPRTrlT2yv462U6xg==\n" +
                  "-----END PUBLIC KEY-----\n"

  wrong_key = OpenSSL::PKey::EC.new(256).to_pem
  payload = {"foo" => "bar"}

  algorithms = {
    JWT::Algorithm::ES256 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.MEUCIQC-pZ8sLcbWCJ1HPuwQTdJgUH6QsoGRuWWU3EbhilcyQwIgL7VE9pIhYhCMzIw2gJWQsW7dS6g1iDGAupk6wPecAvs",
  }

  algorithms.each do |alg, expected_token|
    describe "algorithm #{alg}" do
      it "generates proper token, that can be decoded" do
        # Decode the example
        decoded_token = JWT.decode(expected_token, public_key256, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

        # encode and decode
        token = JWT.encode(payload, private_key256, alg)
        decoded_token = JWT.decode(token, public_key256, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

        decoded_token = JWT.decode(token, private_key256, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})
      end

      describe "#decode" do
        context "when token was signed with another key" do
          it "raises JWT::VerificationError" do
            token = JWT.encode(payload, wrong_key, alg)
            expect_raises(JWT::VerificationError, "Signature verification failed") do
              JWT.decode(token, public_key256, alg)
            end
          end

          it "can ignore verification if requested" do
            token = JWT.encode(payload, wrong_key, alg)
            JWT.decode(token, verify: false)
          end
        end

        context "when token contains not 3 segments" do
          it "raises JWT::DecodeError" do
            ["e30", "e30.e30", "e30.e30.e30.e30"].each do |invalid_token|
              expect_raises(JWT::DecodeError) do
                JWT.decode(invalid_token, public_key256, alg)
              end
            end
          end
        end
      end
    end
  end
end
