require "../../spec_helper"

describe JWT do
  private_key = "-----BEGIN PRIVATE KEY-----\n" +
                "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALn7n7GdaCDE2eeY\n" +
                "JI1sjBNAWNzJrBy+Y+6l5ezXSx+FQAdTG2ZPnMfcAjjomtFk3spXkBzltBbMX1kw\n" +
                "94eqarkUF1iiggXxbuVW1jHbc5Bfm+MVE3QtFjyHI4ovTtSz5pR4zANdfszqjnxc\n" +
                "7huo6HykY6oUuxwICR0A/2UOB4MbAgMBAAECgYBxG3+OdI1sSGvBdnzcaaRy3NJu\n" +
                "TFRZEs0RyWEg/fpZDB/ZlIh4W3ic78eGNqhZKoB4DHK/sE8rAlYGl0oi/thx9u7Z\n" +
                "zUnFaBpy6i17AyTkhg9dSzz1BjcAvkjgEl1mp3ej0rg5bBqS6SR+PEcoUL+CuJ81\n" +
                "rjJVDohmf5e5b8CymQJBAOWbORRqnODSfS3eCYropAP1/lh1cpgZjNg7dJyu2vPn\n" +
                "d97Cp8Nd0sLtMYv2rD28YQW9ITvbu/BHdf74NnpFZi8CQQDPXKpQ2es/DMbHcm4g\n" +
                "0heB/MZOriBJ/7FGNvmoMlQ+cy3gjc+s/JWmbfhpQKCjbqCjb6K0EaPMUNokI5Pi\n" +
                "LOLVAkAmroTqRJ/TXILMVGjlJxZiuHG2M2sv5rYMw898ihTHHIrcU4zx4/+a6Vz8\n" +
                "iH0yFWd/EQLlU7qQ22ksoGKFLOXvAkEAmtHh67m4lXuRkmoSZXjWyluTKD2DqBw7\n" +
                "HGSBZB4nnfTbBPR8YPi5NuiWduckyMEZOM1p2i3tcOfQ5viVOmIu/QJBAOQQKmlh\n" +
                "Dg3R5x6CDXE9Wp/X18ej9YYca5JyN9Q9Mj+TQtomNgzbJx6GKea4seBjep0MmC0R\n" +
                "u3hYblc1DOHJ9o0=\n" +
                "-----END PRIVATE KEY-----\n"

  public_key = "-----BEGIN PUBLIC KEY-----\n" +
               "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5+5+xnWggxNnnmCSNbIwTQFjc\n" +
               "yawcvmPupeXs10sfhUAHUxtmT5zH3AI46JrRZN7KV5Ac5bQWzF9ZMPeHqmq5FBdY\n" +
               "ooIF8W7lVtYx23OQX5vjFRN0LRY8hyOKL07Us+aUeMwDXX7M6o58XO4bqOh8pGOq\n" +
               "FLscCAkdAP9lDgeDGwIDAQAB\n" +
               "-----END PUBLIC KEY-----\n"

  wrong_key = OpenSSL::PKey::RSA.new(1024).to_pem
  payload = {"foo" => "bar"}

  algorithms = {
    JWT::Algorithm::RS256 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.rJUpucYWdjmGiVGHrU4TMwfYNcF52Hm1Q4hJfHhfUPvVL-S0fRHRgwNns90MDOFReXH8_6swbtezzeuQleSY-NdYLEvnXwYHzjLP-Bxc3mrKNMnf8ta1lYB7NqdnIu2nqcNjflJBubn5sIi7-zZew_ohqgMP8H7ptDuICr7ibGQ",
    JWT::Algorithm::RS384 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmb28iOiJiYXIifQ.FfdS8chkIE-PRU61h8VLZgVYvKI3yAvaEpGjqDP0ypGa_0rF6iOCkRuEByhBsH-lCVmKcU-1bp3OsEGXtuYlthpklM76gDDP4YMss2mdH4_xr6P9UQ7lL_xb8inOCbnNMsm7xecIPElDkJ5W22iwF2fbi67p9hlJwgcfBsyfqX4",
    JWT::Algorithm::RS512 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmb28iOiJiYXIifQ.StG6Du1SpGrP7BdFyW6VjMwHudEdekdlJjbT1ByWFPerp7hZ1P7ukHOFMzVVOm6e0xLO6XGk11jDvC_zG2wunjEoMKYY_DuSmUOjVcZVz5m5korH9PJNJRREoQPa42QTVUaMeuv8A3xlq6_SG9wLCGVib4JsIFyS1qPzS3PlNZg",
  }

  algorithms.each do |alg, expected_token|
    describe "algorithm #{alg}" do
      it "generates proper token, that can be decoded" do
        token = JWT.encode(payload, private_key, alg)
        token.should eq(expected_token)

        decoded_token = JWT.decode(token, public_key, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

        decoded_token = JWT.decode(token, private_key, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})
      end

      describe "#decode" do
        context "when token was signed with another key" do
          it "raises JWT::VerificationError" do
            token = JWT.encode(payload, wrong_key, alg)
            expect_raises(JWT::VerificationError, "Signature verification failed") do
              JWT.decode(token, public_key, alg)
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
                JWT.decode(invalid_token, public_key, alg)
              end
            end
          end
        end
      end
    end
  end
end
