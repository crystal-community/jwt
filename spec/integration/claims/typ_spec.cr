require "../../spec_helper"

describe "typ header" do
  context "token does not contain typ" do
    context ":typ option is passed to .decode" do
      it "raises InvalidTypError" do
        # Create a token without typ header (removing default typ)
        payload = {"foo" => "bar"}
        segments = [] of String
        header = {alg: "HS256"}.to_json
        segments << Base64.urlsafe_encode(header, false)
        segments << Base64.urlsafe_encode(payload.to_json, false)
        signature = OpenSSL::HMAC.digest(:sha256, "key", segments.join("."))
        segments << Base64.urlsafe_encode(signature, false)
        token = segments.join(".")

        expect_raises(JWT::InvalidTypError, "Invalid type (typ). Expected \"JWT\", received nothing") do
          JWT.decode(token, "key", JWT::Algorithm::HS256, typ: "JWT")
        end
      end
    end

    context ":typ option is not passed" do
      it "accepts the token" do
        # Create a token without typ header
        payload = {"foo" => "bar"}
        segments = [] of String
        header = {alg: "HS256"}.to_json
        segments << Base64.urlsafe_encode(header, false)
        segments << Base64.urlsafe_encode(payload.to_json, false)
        signature = OpenSSL::HMAC.digest(:sha256, "key", segments.join("."))
        segments << Base64.urlsafe_encode(signature, false)
        token = segments.join(".")

        payload_result, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload_result.should eq({"foo" => "bar"})
      end
    end
  end

  context "token contains typ" do
    context ":typ option is passed" do
      context "typ matches" do
        it "accepts token" do
          token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
          payload, header = JWT.decode(token, "key", JWT::Algorithm::HS256, typ: "JWT")
          payload.should eq({"foo" => "bar"})
          header["typ"].should eq("JWT")
        end

        it "accepts lowercase token" do
          token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256, typ: "jwt")
          payload, header = JWT.decode(token, "key", JWT::Algorithm::HS256, typ: "JWT")
          payload.should eq({"foo" => "bar"})
          header["typ"].should eq("jwt")
        end

        it "accepts token with custom typ" do
          token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256, typ: "at+jwt")
          payload, header = JWT.decode(token, "key", JWT::Algorithm::HS256, typ: "at+jwt")
          payload.should eq({"foo" => "bar"})
          header["typ"].should eq("at+jwt")
        end
      end

      context "typ does not match" do
        it "raises InvalidTypError" do
          token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
          expect_raises(JWT::InvalidTypError, "Invalid type (typ). Expected \"at+jwt\", received \"JWT\"") do
            JWT.decode(token, "key", JWT::Algorithm::HS256, typ: "at+jwt")
          end
        end
      end
    end

    context ":typ option is not passed" do
      it "accepts token" do
        token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
        payload, header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"foo" => "bar"})
        header["typ"].should eq("JWT")
      end
    end
  end

  context "with dynamic key block" do
    it "validates typ with block" do
      token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256, typ: "at+jwt")
      payload, header = JWT.decode(token, typ: "at+jwt") do |_header, _payload|
        "key"
      end
      payload.should eq({"foo" => "bar"})
      header["typ"].should eq("at+jwt")
    end

    it "raises InvalidTypError when typ does not match with block" do
      token = JWT.encode({"foo" => "bar"}, "key", JWT::Algorithm::HS256)
      expect_raises(JWT::InvalidTypError) do
        JWT.decode(token, typ: "at+jwt") do |_header, _payload|
          "key"
        end
      end
    end
  end
end
