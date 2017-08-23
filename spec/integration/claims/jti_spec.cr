require "../../spec_helper"

describe "jti claim" do
  context "token does not contain jti" do
    context ":jti option is passed to .decode" do
      it "raises InvalidJtiError" do
      end
    end
  end

  context "token contains jti" do
    context ":jti option is passed to .decode" do
    end

    context ":jti is not passed to .decode" do
      context "jti matches" do
      end

      context "jti does not match" do
      end
    end
  end
end
