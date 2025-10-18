require "../../spec_helper"

describe "sub claim" do
  context "token does not contain sub" do
    context ":sub option is passed to .decode" do
      it "raises InvalidSubjectError" do
        payload = {"foo" => "bar"}
        token = JWT.encode(payload, "key", JWT::Algorithm::HS256)
        expect_raises(JWT::InvalidSubjectError, "Invalid subject (sub). Expected \"TEJO\", received nothing") do
          JWT.decode(token, "key", JWT::Algorithm::HS256, sub: "TEJO")
        end
      end
    end

    context ":sub option is not passed to .decode" do
      it "accepts token" do
        payload = {"foo" => "bar"}
        token = JWT.encode(payload, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"foo" => "bar"})
      end
    end
  end

  context "token contains sub" do
    context ":sub option is passed to .decode" do
      context "sub does not match" do
        it "raises InvalidSubjectError" do
          payload = {"sub" => "Esperanto"}
          token = JWT.encode(payload, "key", JWT::Algorithm::HS256)
          expect_raises(JWT::InvalidSubjectError, "Invalid subject (sub). Expected \"Junularo\", received \"Esperanto\"") do
            JWT.decode(token, "key", JWT::Algorithm::HS256, sub: "Junularo")
          end
        end
      end

      context "sub matches" do
        it "accepts the token" do
          payload = {"sub" => "Esperanto"}
          token = JWT.encode(payload, "key", JWT::Algorithm::HS256)
          payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256, sub: "Esperanto")
          payload.should eq({"sub" => "Esperanto"})
        end
      end
    end

    context ":sub option is not passed to .decode" do
      it "accepts token" do
        payload = {"sub" => "Esperanto"}
        token = JWT.encode(payload, "key", JWT::Algorithm::HS256)
        payload, _header = JWT.decode(token, "key", JWT::Algorithm::HS256)
        payload.should eq({"sub" => "Esperanto"})
      end
    end
  end
end
