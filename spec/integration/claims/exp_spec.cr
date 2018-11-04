require "../../spec_helper"

describe "exp claim" do
  context "exp is in the future" do
    it "token is accepted" do
      exp = Time.now.to_unix + 10
      payload = {"exp" => exp}
      token = JWT.encode(payload, "key", "HS256")
      payload, header = JWT.decode(token, "key", "HS256")
      payload.should eq({"exp" => exp})
    end
  end

  context "exp is in the past" do
    it "raises VerificationError" do
      exp = Time.now.to_unix - 1
      payload = {"exp" => exp}
      token = JWT.encode(payload, "key", "HS256")
      expect_raises(JWT::ExpiredSignatureError, "Signature is expired") do
        JWT.decode(token, "key", "HS256")
      end
    end
  end
end
