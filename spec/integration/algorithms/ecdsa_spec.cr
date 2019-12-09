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
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.MEUCIQC-pZ8sLcbWCJ1HPuwQTdJgUH6QsoGRuWWU3EbhilcyQwIgL7VE9pIhYhCMzIw2gJWQsW7dS6g1iDGAupk6wPecAvs",
    },

    JWT::Algorithm::ES384 => {
      "-----BEGIN EC PRIVATE KEY-----\n" +
      "MIGkAgEBBDBfbYWrSPvOC+KI7viJp4p0ZDu225CMXqzZ6psAja5JOur6kPU2Bj+1\n" +
      "mE0qtiXaVgGgBwYFK4EEACKhZANiAAQG0H1oa1HMsWVXKL8pi7PqrfY3QYnh5qRg\n" +
      "bIZkFLnnOikYnfy4+C4ldfja4Q1Sol2nnsQFntbkK0LMDwuJfh1hF9qUDyUnWNcZ\n" +
      "Evgh9T/ee7vu8MwVeAfqVHhby7xlCnk=\n" +
      "-----END EC PRIVATE KEY-----\n",
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.MGYCMQC74uyfqBTV0Dqv6PItwrJpfXo-1zghUY0Zc0mRanHNb7KuLN14gy31QqIZSGw7b7MCMQC_M2ZjMwmls337zPJAKfG-_M0zTqs_2kXuc1qDgEgH-k_iScDgft50RYcABWn9Qcc",
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
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.MIGHAkEHNBnCBCQj6vbASvrQ_eDqfAZzi_6yXY4keA_HhVnR7rAU2C1cv06Smil55RcrzLJjUx2NDWabwnHz6UR5Q3g4fAJCAfPP43s8FHuAd2aaITOZFb-sZ-pEun8tl8jnFC2J4DJj-i0Y2EcE3m_O898T8EZfJDmZz_BJaOWGmPkUG4S_-LOX",
    },
  }

  algorithms.each do |alg, (private_key, expected_token)|
    public_key = OpenSSL::PKey::EC.new(private_key).public_key.to_pem

    describe "algorithm #{alg}" do
      it "generates proper token, that can be decoded" do
        # encode and decode
        token = JWT.encode(payload, private_key, alg)
        decoded_token = JWT.decode(token, public_key, alg)
        decoded_token[0].should eq(payload)
        decoded_token[1].should eq({"typ" => "JWT", "alg" => alg.to_s})

        # Decode the example
        decoded_token = JWT.decode(expected_token, public_key, alg)
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
