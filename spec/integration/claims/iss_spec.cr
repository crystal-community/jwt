require "../../spec_helper"

describe "iss claim" do
  context "token does not contain iss" do
    context ":iss option is passed to .decode" do
      it "raises InvalidIssuerError" do
        token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
        expect_raises(JWT::InvalidIssuerError, "Invalid issuer (iss). Expected \"TEJO\", received nothing") do
          JWT.decode(token, "key", JWT::Algorithm::HS256, iss: "TEJO")
        end
      end
    end

    context ":iss option is not passed" do
      it "accepts the token" do
        token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"foo" => "bar"})
      end
    end
  end

  context "token contains iss" do
    context ":iss option is passed" do
      context "iss matches" do
        it "accepts token" do
          token = JWT.encode({"iss" => "TEJO"}, "key", JWT::Algorithm::HS256)
          payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256, iss: "TEJO")
          payload.should eq({"iss" => "TEJO"})
        end
      end

      context "iss does not match" do
        it "raises InvalidIssuerError" do
          token = JWT.encode({"iss" => "TEJO"}, "key", JWT::Algorithm::HS256)
          expect_raises(JWT::InvalidIssuerError, "Invalid issuer (iss). Expected \"UEA\", received \"TEJO\"") do
            JWT.decode(token, "key", JWT::Algorithm::HS256, iss: "UEA")
          end
        end
      end
    end

    context ":iss option is not passed" do
      it "accepts token" do
        token = JWT.encode({"iss" => "TEJO"}, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"iss" => "TEJO"})
      end
    end
  end
end
