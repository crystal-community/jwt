require "../../spec_helper"

describe JWT do
  secret_key = "$ecretKey"
  wrong_key = "WrongKey"
  payload = {"foo" => "bar"}

  algorithms = [
    ["HS256", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.JrpaO9b4_55fVBXe8LgOIkKBTjSE7-pqm5pfzh9wzOM"],
    ["HS384", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJmb28iOiJiYXIifQ.l7UMuFdyQGfcI06CfxK9xk7NmGbRShs7IDdQ5qVi8MXlaCn1o6WEQyJTduOEbPhp"],
    ["HS512", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmb28iOiJiYXIifQ.cuIGPzgyhGTXJzO7FojzjcH7wZDc2005e1MChS-5KJOo1ON4g_k3ZSyxcKiE7rK8VJuVnL7X7EM2GQG2mVgOxQ"],
  ]

  algorithms.each do |alg_data|
    alg, expected_token = alg_data

    describe "algorithm #{alg}" do
      it "generates proper token, that can be decoded" do
        token = JWT.encode(payload, secret_key, alg)
        token.should eq(expected_token)

        decoded_token = JWT.decode(token, secret_key, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg})
      end

      describe "#decode" do
        context "when token was signed with another key" do
          context "when verify argument is true" do
            it "raises JWT::VerificationError" do
              token = JWT.encode(payload, wrong_key, alg)
              expect_raises(JWT::VerificationError, "Signature verification failed") do
                JWT.decode(token, secret_key, alg)
              end
            end
          end

          context "when verify argument is false" do
            it "decodes the token" do
              token = JWT.encode(payload, wrong_key, alg)

              decoded_token = JWT.decode(token, "", alg, verify: false)

              decoded_token[0].should eq(payload)
              decoded_token[1].should eq({"typ" => "JWT", "alg" => alg})
            end
          end
        end

        context "when token contains not 3 segments" do
          it "raises JWT::DecodeError" do
            ["e30", "e30.e30", "e30.e30.e30.e30"].each do |invalid_token|
              expect_raises(JWT::DecodeError) do
                JWT.decode(invalid_token, secret_key, alg)
              end
            end
          end
        end
      end
    end
  end
end
