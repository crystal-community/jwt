require "../../spec_helper"

describe "aud claim" do
  context "token does not contain aud" do
    context "aud options is not passed to .decode method" do
      it "accepts token" do
        token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"foo" => "bar"})
      end
    end

    context "aud option is passed" do
      it "raises InvalidAudienceError" do
        token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
        expect_raises(JWT::InvalidAudienceError, "Invalid audience (aud). Expected \"sergey\", received nothing") do
          JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "sergey")
        end
      end
    end
  end

  context "token contains aud as a string" do
    context "aud is not passed to .decode" do
      it "accepts token" do
        token = JWT.encode({"foo" => "bar", "aud" => "sergey"}, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"foo" => "bar", "aud" => "sergey"})
      end
    end

    context "aud matches" do
      it "accepts token" do
        token = JWT.encode({"foo" => "bar", "aud" => "sergey"}, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "sergey")
        payload.should eq({"foo" => "bar", "aud" => "sergey"})
      end
    end

    context "aud does not match" do
      it "raises InvalidAudienceError" do
        token = JWT.encode({"foo" => "bar", "aud" => "sergey"}, "key", JWT::Algorithm::HS256)
        expect_raises(JWT::InvalidAudienceError, "Invalid audience (aud). Expected \"julia\", received \"sergey\"") do
          JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "julia")
        end
      end
    end
  end

  context "token contains aud as an array of strings" do
    context "aud is not passed to .decode" do
      it "accepts token" do
        token = JWT.encode({"foo" => "bar", "aud" => ["sergey", "julia"]}, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"foo" => "bar", "aud" => ["sergey", "julia"]})
      end
    end

    context "aud matches one of items in the array" do
      it "accepts token" do
        token = JWT.encode({"foo" => "bar", "aud" => ["sergey", "julia"]}, "key", JWT::Algorithm::HS256)

        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "julia")
        payload.should eq({"foo" => "bar", "aud" => ["sergey", "julia"]})

        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "sergey")
        payload.should eq({"foo" => "bar", "aud" => ["sergey", "julia"]})
      end
    end

    context "aud does not match" do
      it "raises InvalidAudienceError" do
        token = JWT.encode({"foo" => "bar", "aud" => ["sergey", "julia"]}, "key", JWT::Algorithm::HS256)

        expect_raises(JWT::InvalidAudienceError, "Invalid audience (aud). Expected \"max\", received [\"sergey\", \"julia\"]") do
          JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "max")
        end
      end
    end
  end

  context "token contains invalid format of aud" do
    it "raises exception" do
      token = JWT.encode({"foo" => "bar", "aud" => 123}, "key", JWT::Algorithm::HS256)
      expect_raises(JWT::InvalidAudienceError, "aud claim must be a string or array of strings") do
        JWT.decode(token, "key", JWT::Algorithm::HS256, aud: "max")
      end
    end
  end
end
