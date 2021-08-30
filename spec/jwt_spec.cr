require "./spec_helper"

describe JWT do
  describe "#encode" do
    it "encodes with HS256" do
      payload = {"k1" => "v1", "k2" => "v2"}
      key = "SecretKey"
      token = JWT.encode(payload, key, JWT::Algorithm::HS256)
      token.should eq "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
    end
  end

  describe "#decode" do
    it "decodes and verifies JWT" do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
      payload, header = JWT.decode(token, "SecretKey", JWT::Algorithm::HS256)
      header.should eq({"typ" => "JWT", "alg" => "HS256"})
      payload.should eq({"k1" => "v1", "k2" => "v2"})
    end

    it "decodes and verifies JWT with dynamic key" do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
      payload, header = JWT.decode(token, algorithm: JWT::Algorithm::HS256) do |_header, _payload|
        "SecretKey"
      end
      header.should eq({"typ" => "JWT", "alg" => "HS256"})
      payload.should eq({"k1" => "v1", "k2" => "v2"})
    end

    it "decodes and verifies JWT with dynamic key and auto algorithm" do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
      payload, header = JWT.decode(token) do |_header, _payload|
        "SecretKey"
      end
      header.should eq({"typ" => "JWT", "alg" => "HS256"})
      payload.should eq({"k1" => "v1", "k2" => "v2"})
    end
  end

  describe "#encode_header" do
    it "encodes header using Base64" do
      encoded_header = JWT.encode_header(JWT::Algorithm::HS256)
      header = Base64.decode_string(encoded_header)
      header.should eq %({"typ":"JWT","alg":"HS256"})
    end
  end

  describe "#encode_payload" do
    it "encodes payload with Base64" do
      encoded_payload = JWT.encode_payload({"name" => "Sergey", "drink" => "mate"})
      payload_json = Base64.decode_string(encoded_payload)
      payload_json.should eq %({"name":"Sergey","drink":"mate"})
    end
  end

  describe "#sign" do
    context "when algorithm is none" do
      it "returns an empty string" do
        result = JWT.encoded_signature(JWT::Algorithm::None, "key", "data")
        result.should eq ""
      end
    end

    context "when algorithm is HS256" do
      it "returns signature" do
        result = JWT.encoded_signature(JWT::Algorithm::HS256, "key", "data")
        result.should eq "UDH-PZicbRU3oBP6bnOdojRj_a7DtwE32Cjjas4iG9A"
      end
    end
  end
end
