require "../../spec_helper"

describe JWT do
  secret_key = "-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC5+5+xnWggxNnnmCSNbIwTQFjcyawcvmPupeXs10sfhUAHUxtm
T5zH3AI46JrRZN7KV5Ac5bQWzF9ZMPeHqmq5FBdYooIF8W7lVtYx23OQX5vjFRN0
LRY8hyOKL07Us+aUeMwDXX7M6o58XO4bqOh8pGOqFLscCAkdAP9lDgeDGwIDAQAB
AoGAcRt/jnSNbEhrwXZ83GmkctzSbkxUWRLNEclhIP36WQwf2ZSIeFt4nO/Hhjao
WSqAeAxyv7BPKwJWBpdKIv7Ycfbu2c1JxWgacuotewMk5IYPXUs89QY3AL5I4BJd
Zqd3o9K4OWwakukkfjxHKFC/grifNa4yVQ6IZn+XuW/AspkCQQDlmzkUapzg0n0t
3gmK6KQD9f5YdXKYGYzYO3Scrtrz53fewqfDXdLC7TGL9qw9vGEFvSE727vwR3X+
+DZ6RWYvAkEAz1yqUNnrPwzGx3JuINIXgfzGTq4gSf+xRjb5qDJUPnMt4I3PrPyV
pm34aUCgo26go2+itBGjzFDaJCOT4izi1QJAJq6E6kSf01yCzFRo5ScWYrhxtjNr
L+a2DMPPfIoUxxyK3FOM8eP/mulc/Ih9MhVnfxEC5VO6kNtpLKBihSzl7wJBAJrR
4eu5uJV7kZJqEmV41spbkyg9g6gcOxxkgWQeJ5302wT0fGD4uTbolnbnJMjBGTjN
adot7XDn0Ob4lTpiLv0CQQDkECppYQ4N0ecegg1xPVqf19fHo/WGHGuScjfUPTI/
k0LaJjYM2ycehinmuLHgY3qdDJgtEbt4WG5XNQzhyfaN
-----END RSA PRIVATE KEY-----"

  wrong_key = OpenSSL::RSA.new(1024).to_pem
  payload = {"foo" => "bar"}

  algorithms = [
    ["RS256", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.rJUpucYWdjmGiVGHrU4TMwfYNcF52Hm1Q4hJfHhfUPvVL-S0fRHRgwNns90MDOFReXH8_6swbtezzeuQleSY-NdYLEvnXwYHzjLP-Bxc3mrKNMnf8ta1lYB7NqdnIu2nqcNjflJBubn5sIi7-zZew_ohqgMP8H7ptDuICr7ibGQ"],
    ["RS384", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmb28iOiJiYXIifQ.FfdS8chkIE-PRU61h8VLZgVYvKI3yAvaEpGjqDP0ypGa_0rF6iOCkRuEByhBsH-lCVmKcU-1bp3OsEGXtuYlthpklM76gDDP4YMss2mdH4_xr6P9UQ7lL_xb8inOCbnNMsm7xecIPElDkJ5W22iwF2fbi67p9hlJwgcfBsyfqX4"],
    ["RS512", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmb28iOiJiYXIifQ.StG6Du1SpGrP7BdFyW6VjMwHudEdekdlJjbT1ByWFPerp7hZ1P7ukHOFMzVVOm6e0xLO6XGk11jDvC_zG2wunjEoMKYY_DuSmUOjVcZVz5m5korH9PJNJRREoQPa42QTVUaMeuv8A3xlq6_SG9wLCGVib4JsIFyS1qPzS3PlNZg"],
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
          it "raises JWT::VerificationError" do
            token = JWT.encode(payload, wrong_key, alg)
            expect_raises(JWT::VerificationError, "Signature verification failed") do
              JWT.decode(token, secret_key, alg)
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
