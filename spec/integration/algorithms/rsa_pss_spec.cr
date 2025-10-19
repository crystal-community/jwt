require "../../spec_helper"

{% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
  describe JWT do
    # 1024-bit key (adequate for PS256/PS384, but too small for PS512)
    private_key_1024 = "-----BEGIN PRIVATE KEY-----\n" +
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

    public_key_1024 = "-----BEGIN PUBLIC KEY-----\n" +
                      "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5+5+xnWggxNnnmCSNbIwTQFjc\n" +
                      "yawcvmPupeXs10sfhUAHUxtmT5zH3AI46JrRZN7KV5Ac5bQWzF9ZMPeHqmq5FBdY\n" +
                      "ooIF8W7lVtYx23OQX5vjFRN0LRY8hyOKL07Us+aUeMwDXX7M6o58XO4bqOh8pGOq\n" +
                      "FLscCAkdAP9lDgeDGwIDAQAB\n" +
                      "-----END PUBLIC KEY-----\n"

    # 2048-bit key (required for PS512)
    private_key_2048 = OpenSSL::PKey::RSA.new(2048).to_pem
    public_key_2048 = OpenSSL::PKey::RSA.new(private_key_2048).public_key.to_pem

    payload = {"foo" => "bar"}

    # PS256 and PS384 with 1024-bit key
    [JWT::Algorithm::PS256, JWT::Algorithm::PS384].each do |alg|
      describe "algorithm #{alg}" do
        it "generates token that can be decoded" do
          token = JWT.encode(payload, private_key_1024, alg)

          decoded_token = JWT.decode(token, public_key_1024, alg)
          decoded_token[0].should eq(payload)
          decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

          decoded_token = JWT.decode(token, private_key_1024, alg)
          decoded_token[0].should eq(payload)
          decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})
        end

        it "can encode and decode with different instances" do
          token1 = JWT.encode(payload, private_key_1024, alg)
          token2 = JWT.encode(payload, private_key_1024, alg)

          # PSS uses random salt, so tokens should be different
          token1.should_not eq(token2)

          # But both should decode successfully
          JWT.decode(token1, public_key_1024, alg)[0].should eq(payload)
          JWT.decode(token2, public_key_1024, alg)[0].should eq(payload)
        end

        describe "#decode" do
          context "when token was signed with another key" do
            wrong_key = OpenSSL::PKey::RSA.new(1024).to_pem

            it "raises JWT::VerificationError" do
              token = JWT.encode(payload, wrong_key, alg)
              expect_raises(JWT::VerificationError, "Signature verification failed") do
                JWT.decode(token, public_key_1024, alg)
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
                  JWT.decode(invalid_token, public_key_1024, alg)
                end
              end
            end
          end
        end
      end
    end

    # PS512 requires 2048-bit key
    describe "algorithm PS512" do
      it "generates token that can be decoded" do
        token = JWT.encode(payload, private_key_2048, JWT::Algorithm::PS512)

        decoded_token = JWT.decode(token, public_key_2048, JWT::Algorithm::PS512)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => "PS512"})

        decoded_token = JWT.decode(token, private_key_2048, JWT::Algorithm::PS512)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => "PS512"})
      end

      it "can encode and decode with different instances" do
        token1 = JWT.encode(payload, private_key_2048, JWT::Algorithm::PS512)
        token2 = JWT.encode(payload, private_key_2048, JWT::Algorithm::PS512)

        # PSS uses random salt, so tokens should be different
        token1.should_not eq(token2)

        # But both should decode successfully
        JWT.decode(token1, public_key_2048, JWT::Algorithm::PS512)[0].should eq(payload)
        JWT.decode(token2, public_key_2048, JWT::Algorithm::PS512)[0].should eq(payload)
      end

      describe "#decode" do
        context "when token was signed with another key" do
          wrong_key = OpenSSL::PKey::RSA.new(2048).to_pem

          it "raises JWT::VerificationError" do
            token = JWT.encode(payload, wrong_key, JWT::Algorithm::PS512)
            expect_raises(JWT::VerificationError, "Signature verification failed") do
              JWT.decode(token, public_key_2048, JWT::Algorithm::PS512)
            end
          end

          it "can ignore verification if requested" do
            token = JWT.encode(payload, wrong_key, JWT::Algorithm::PS512)
            JWT.decode(token, verify: false)
          end
        end

        context "when token contains not 3 segments" do
          it "raises JWT::DecodeError" do
            ["e30", "e30.e30", "e30.e30.e30.e30"].each do |invalid_token|
              expect_raises(JWT::DecodeError) do
                JWT.decode(invalid_token, public_key_2048, JWT::Algorithm::PS512)
              end
            end
          end
        end
      end
    end
  end
{% end %}
