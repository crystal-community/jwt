require "../../spec_helper"

describe JWT do
  wrong_key = OpenSSL::PKey::EC.new(256).to_pem
  payload = {"foo" => "bar"}

  # To generate a key: OpenSSL::PKey::EC.new(521)
  algorithms = {
    JWT::Algorithm::ES256 => {
      "-----BEGIN EC PRIVATE KEY-----\n" +
      "MHcCAQEEICQ13objo8V5wNl7ioToptpI6nJ2fvNcy+fgWQ2BrzgnoAoGCCqGSM49\n" +
      "AwEHoUQDQgAEUeAfjUi57m5PZ7UEiaBLUzex/Jsq0l+dC5XixCUe01qqZJ3vFe7e\n" +
      "zVdalVZaibmLJQ2VUgPRTrlT2yv462U6xg==\n" +
      "-----END EC PRIVATE KEY-----\n",
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.FG1b5ByP6eIoXsXvrdTpjP4fwGWOj1qxeyPkxyXulsPYUYVor5Va8uSGUkrn41lUrR9gC1LiwnY1XPXEC_CDsA",
    },

    JWT::Algorithm::ES384 => {
      "-----BEGIN EC PRIVATE KEY-----\n" +
      "MIGkAgEBBDBfbYWrSPvOC+KI7viJp4p0ZDu225CMXqzZ6psAja5JOur6kPU2Bj+1\n" +
      "mE0qtiXaVgGgBwYFK4EEACKhZANiAAQG0H1oa1HMsWVXKL8pi7PqrfY3QYnh5qRg\n" +
      "bIZkFLnnOikYnfy4+C4ldfja4Q1Sol2nnsQFntbkK0LMDwuJfh1hF9qUDyUnWNcZ\n" +
      "Evgh9T/ee7vu8MwVeAfqVHhby7xlCnk=\n" +
      "-----END EC PRIVATE KEY-----\n",
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.Gpkkby0V5KBrpi09bQxgs2CDs-joh8RL1fmVhd-sAgUplJZS1-IwsFAh2-si7Mcf9RIp4OKA3QaMICYut3Or3ewj5rYuwOw4qhBUITYPveBgXhPknM_svg2Le44ZL1Zx",
    },

    # https://tools.ietf.org/html/rfc7518#section-3.4
    # NOTE:: key size 521 for ES512
    JWT::Algorithm::ES512 => {
      "-----BEGIN EC PRIVATE KEY-----\n" +
      "MIHcAgEBBEIBUqevSmQr97G1/QaHaORzABsXB7oFH9kQ3ofpzyDWRMuoUAO1yuKU\n" +
      "XDLvv6K2bla/6Jjajs0iaFtYfjQkELmquPqgBwYFK4EEACOhgYkDgYYABADKd6je\n" +
      "zsb/nsKV2Fgftt+uzKGFTiq9QD2jvo/xbwEKO/JMc9okIO6S2D8PxvtaM8V5uWa/\n" +
      "36XJ4ZqYMFyT4r6SFQCJ+0zfMTvZWiLZxSoPaUhd/amPe5NBM3qy2qdNBXjW8SW4\n" +
      "r8wUDIQIjFY3yId6nm7UoILcWV2DfH9zG2ZlaRuivg==\n" +
      "-----END EC PRIVATE KEY-----\n",
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AeXp0TWi_GK76s0Skjltw5a03EjmwndrBCGld4aOATastK7WAymbHIfXSJW6G5YhHYQ0N8unnWKQtr1SGUsAntiIARbP_dEaYvdmZu_5ypZ_fhxCymRYQ0hIxRNVclxdEGO9P6ckBRXtGfyCEGyBr3Czn6fogCrfRe0epUvyNRWUvuNH",
    },
  }

  describe "ES* ASN1 conversion" do
    it "raw to ASN1" do
      key_raw, example = algorithms[JWT::Algorithm::ES256]
      private_key = OpenSSL::PKey::EC.new(key_raw)
      public_key = private_key.public_key

      _verify_data, _, encoded_signature = example.rpartition('.')
      signature = Base64.decode(encoded_signature)

      JWT.raw_to_asn1(signature, public_key).should eq(
        Bytes[
          48, 69, 2, 32, 20, 109, 91, 228, 28, 143, 233, 226, 40, 94, 197,
          239, 173, 212, 233, 140, 254, 31, 192, 101, 142, 143, 90, 177, 123,
          35, 228, 199, 37, 238, 150, 195, 2, 33, 0, 216, 81, 133, 104, 175,
          149, 90, 242, 228, 134, 82, 74, 231, 227, 89, 84, 173, 31, 96, 11, 82,
          226, 194, 118, 53, 92, 245, 196, 11, 240, 131, 176,
        ]
      )
    end
  end

  algorithms.each do |alg, (private_key, example_token)|
    describe "algorithm #{alg}" do
      public_key = OpenSSL::PKey::EC.new(private_key).public_key.to_pem

      it "generates proper token, that can be decoded" do
        # encode and decode
        token = JWT.encode(payload, private_key, alg)
        decoded_token = JWT.decode(token, public_key, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

        # Decode the example
        decoded_token = JWT.decode(example_token, public_key, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

        decoded_token = JWT.decode(example_token, private_key, alg)
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
