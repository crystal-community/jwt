require "../../spec_helper"

describe "none algorithm" do
  alg = JWT::Algorithm::None
  secret_key = "$ecretKey"
  payload = {"foo" => "bar"}
  expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ."

  it "generates proper token, that can be decoded" do
    token = JWT.encode(payload, secret_key, alg)
    token.should eq(expected_token)

    decoded_token = JWT.decode(token, secret_key, alg)
    decoded_token[0].should eq(payload)
    decoded_token[1].should eq({"typ" => "JWT", "alg" => "none"})
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
