require "../../spec_helper"

# This spec verifies compatibility with tokens from the l8w8jwt library
# Reference: https://github.com/GlitchedPolygons/l8w8jwt/blob/master/examples/ps256/decode.c
describe "PS256 decode compatibility" do
  # Token from l8w8jwt example
  jwt_token = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE1ODAzNDAwMzcsImV4cCI6MTU4MDM0MDYzNywic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.X4o81UkLLt1mBdoQozWPAtVIRvkX7249fs25FGqrlGzci2exAVQh6g8OzqZlhPO8_VSVGt1bTlurWPhrPwZoeViy1g86MRBLNoiuWEkPg0FFB2jhBPGF2u-cJ2YKd9VSLSjs1fcxSyfG5dKczDo_w3FUL_syNpOpWaWtvByxDn0Cez4SHfTIcaGPKsyYBKhy1t3RgFzm9mCMugRd40omPO4WFKQ1f-boO0ydfvcybEmxMBpT3DsqbKAD9oM0kFWsLMIzOXIp4Uo1J-k3utjieDwaiBu7x2g-bU_0XygnXWIfrSXtUOmntVVFe9am13fIeH-I_3SJlzhLI4QapJ-_s5xeyZ3Y8tHLs-Sqt85Bs_rnewnJpHESXn-G5eK7YTHEvC3luELNrGQlTzQIpTZLYwARikQlhBme-lqvH6hTdGwQy-jhlr41GF5hBKHArFTN0RJBRDKyGgJffDlDDsk3g9NpaZqvOqMvLBHk78TbrQnTKMKY6L7dnAoPcTcl8IgIr9lN37TKFuvAm6nDjcWQUViOO9YtDng3e8cjWaJiizGpTOct-IKn7ZXMzGRrFSmXSOWgeukP5jcwH5dU_0ICDbt2oaid7Bpm1z8EviBGNh0OmjqJ8FmsGst8zaAufpSBwCbV9OCUo84RminY6pW6Lm3BWwIbki-yUOExAWJPjN0"

  # RSA 4096-bit public key from l8w8jwt example
  rsa_public_key = "-----BEGIN PUBLIC KEY-----\n" +
                   "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoWFe7BbX1nWo5oaSv/Jv\n" +
                   "IUCWsk/Vi2q8P0cGkefgN5J7MN7Kfv7lq0hl/1cZcJs81IC+GiC+V3aR2zLBNnJJ\n" +
                   "axa4sqk+hF5DJcD2bF0B80uqPYQUXlQwki/heATnVcke8APuY0kOZykxoD0APAqw\n" +
                   "0z5KDqgt2vA9G6keM6b9bbL+IvxM+yMk1QV0OQLh6Rkz46DyPSoUFWyXiist47PJ\n" +
                   "KNyZAfFZx6vEivzBmqRHKe11W9oD/tN5VTQCH/UTSRfyWq/UUMFVMCksLwT6XoWI\n" +
                   "7F5swgQkSahWkVJ93Qf8cUf1HIZYTMJBYPG4y2NDZ0+ytnH3BNXLMQXg9xbgv6B/\n" +
                   "iaSVScI4CWIpQTAtNKnJwYg2+RhfYBC07iM56c4a+TjbCWgmd11UYc96dbw83uFR\n" +
                   "jKZc3+SC38ITCgMuoDPNBlFJK6u8VfYylGEJolGcauVa6yZKwzsJGr5J/LANz+Zy\n" +
                   "HZmANed+2Hjqxu/H1NGDBdvUGLQbhb/uBJ8oG8iAW5eUyjEJMX0RuncYnBrUjZdE\n" +
                   "Fr0zJd5VkrfFTd26AjGusbiBevATfj83SNa9uK3N3lSNcLNyNXUjmfOU21NWHAk5\n" +
                   "QV3TJb6SCTcqWFaYoyKR7H6zxRcArNuIAMW4KhOl4jdNnTxJllC4tr/gkE+uO1nt\n" +
                   "B9ymLxQBRp8osHjuZpKXr3cCAwEAAQ==\n" +
                   "-----END PUBLIC KEY-----"

  it "can decode a PS256 token from l8w8jwt library" do
    # Decode without verification or validation (since token is expired)
    payload, header = JWT.decode(jwt_token, verify: false, validate: false)

    # Verify header
    header["alg"].should eq("PS256")
    header["typ"].should eq("JWT")
    header["kid"].should eq("some-key-id-here-012345")

    # Verify payload claims
    payload["iat"].should eq(1580340037)
    payload["exp"].should eq(1580340637)
    payload["sub"].should eq("Gordon Freeman")
    payload["iss"].should eq("Black Mesa")
    payload["aud"].should eq("Administrator")
    payload["ctx"].should eq("Unforseen Consequences")
    payload["age"].should eq(27)
    payload["size"].should eq(1.85)
    payload["alive"].should eq(true)
    payload["nulltest"].as_nil.should be_nil
  end

  it "can verify the PS256 signature with the public key" do
    # Verify signature (verify: true checks signature, validate: false skips expiry check)
    payload, _header = JWT.decode(jwt_token, rsa_public_key, JWT::Algorithm::PS256, verify: true, validate: false)

    # Signature is valid, verify payload
    payload["sub"].should eq("Gordon Freeman")
    payload["iss"].should eq("Black Mesa")
    payload["aud"].should eq("Administrator")
    payload["ctx"].should eq("Unforseen Consequences")
  end

  it "distinguishes between signature verification and claim validation" do
    # verify: true, validate: false -> checks signature but not expiry
    payload, _ = JWT.decode(jwt_token, rsa_public_key, JWT::Algorithm::PS256, verify: true, validate: false)
    payload["sub"].should eq("Gordon Freeman")

    # verify: false, validate: false -> no checks at all
    payload, _ = JWT.decode(jwt_token, verify: false, validate: false)
    payload["sub"].should eq("Gordon Freeman")

    # verify: true, validate: true -> checks signature AND expiry (will fail)
    expect_raises(JWT::ExpiredSignatureError) do
      JWT.decode(jwt_token, rsa_public_key, JWT::Algorithm::PS256, verify: true, validate: true)
    end
  end

  # Note: Validation tests (iss, sub, aud) are not included here because
  # the token is expired and validation checks exp first. The existing
  # claim validation tests in other specs cover those features.

  it "properly decodes all data types in payload" do
    payload, _ = JWT.decode(jwt_token, verify: false, validate: false)

    # Integer
    payload["age"].as_i.should eq(27)

    # Float
    payload["size"].as_f.should eq(1.85)

    # Boolean
    payload["alive"].as_bool.should eq(true)

    # Null (JSON null is represented as JSON::Any, use .as_nil to extract)
    payload["nulltest"].as_nil.should be_nil

    # Strings
    payload["sub"].as_s.should eq("Gordon Freeman")
    payload["ctx"].as_s.should eq("Unforseen Consequences")
  end

  it "token is expired and should fail exp validation" do
    # Token exp is 1580340637 (2020-01-29 23:30:37 UTC), which has passed
    expect_raises(JWT::ExpiredSignatureError, "Signature is expired") do
      JWT.decode(jwt_token, rsa_public_key, JWT::Algorithm::PS256)
    end
  end
end
