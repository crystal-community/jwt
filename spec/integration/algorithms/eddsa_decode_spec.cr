require "../../spec_helper"

# This spec verifies compatibility with tokens from the l8w8jwt library
# Reference: https://github.com/GlitchedPolygons/l8w8jwt/blob/master/examples/eddsa/decode.c
describe "EdDSA decode compatibility" do
  # Token from l8w8jwt example
  jwt_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImt0eSI6IkVDIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE2MTA3MzQwMDEsImV4cCI6MTYxMDczNDYwMSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.DoXYMXT7tCt51V0QdziP7NObCSsTKc_sqZUFY14nX_uPLL4LfYorQtwi3zFNVF9act_Nz5LruvH16XIxSderCA"

  # Ed25519 keys from l8w8jwt example (hex-encoded)
  # Note: l8w8jwt's "private key" is 64 bytes: 32-byte seed + 32-byte public key
  # We use only the first 32 bytes (seed) for signing/verification
  ed25519_private_key_full = "4070f09e0040304000e0f0200e1c00a058c49d1db349cbec05bf412615aad05c4675103fa2eb4d570875d58476426818cfe37b62e751b7092ee4a6606c8b7ca2"
  ed25519_private_key = ed25519_private_key_full[0, 64] # First 32 bytes (64 hex chars)
  # ed25519_public_key = "4675103fa2eb4d570875d58476426818cfe37b62e751b7092ee4a6606c8b7ca2"

  it "can decode an EdDSA token from l8w8jwt library" do
    # Decode without verification or validation (since token is expired)
    payload, header = JWT.decode(jwt_token, verify: false, validate: false)

    # Verify header
    header["alg"].should eq("EdDSA")
    header["typ"].should eq("JWT")
    header["kty"].should eq("EC")
    header["crv"].should eq("Ed25519")
    header["kid"].should eq("some-key-id-here-012345")

    # Verify payload claims
    payload["iat"].should eq(1610734001)
    payload["exp"].should eq(1610734601)
    payload["sub"].should eq("Gordon Freeman")
    payload["iss"].should eq("Black Mesa")
    payload["aud"].should eq("Administrator")
    payload["ctx"].should eq("Unforseen Consequences")
    payload["age"].should eq(27)
    payload["size"].should eq(1.85)
    payload["alive"].should eq(true)
    payload["nulltest"].as_nil.should be_nil
  end

  it "can verify the EdDSA signature with the private key" do
    # EdDSA verification works with private key (derives public key internally)
    # verify: true checks signature, validate: false skips expiry check
    payload, _header = JWT.decode(jwt_token, ed25519_private_key, JWT::Algorithm::EdDSA, verify: true, validate: false)

    # Signature is valid, verify payload
    payload["sub"].should eq("Gordon Freeman")
    payload["iss"].should eq("Black Mesa")
    payload["aud"].should eq("Administrator")
    payload["ctx"].should eq("Unforseen Consequences")
  end

  it "distinguishes between signature verification and claim validation" do
    # verify: true, validate: false -> checks signature but not expiry
    payload, _ = JWT.decode(jwt_token, ed25519_private_key, JWT::Algorithm::EdDSA, verify: true, validate: false)
    payload["sub"].should eq("Gordon Freeman")

    # verify: false, validate: false -> no checks at all
    payload, _ = JWT.decode(jwt_token, verify: false, validate: false)
    payload["sub"].should eq("Gordon Freeman")

    # verify: true, validate: true -> checks signature AND expiry (will fail)
    expect_raises(JWT::ExpiredSignatureError) do
      JWT.decode(jwt_token, ed25519_private_key, JWT::Algorithm::EdDSA, verify: true, validate: true)
    end
  end

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

    # Unix timestamps
    payload["iat"].as_i.should eq(1610734001) # 2021-01-15 18:40:01 UTC
    payload["exp"].as_i.should eq(1610734601) # 2021-01-15 18:50:01 UTC (10 minutes later)
  end

  it "token is expired and should fail exp validation" do
    # Token exp is 1610734601 (2021-01-15 18:50:01 UTC), which has passed
    expect_raises(JWT::ExpiredSignatureError, "Signature is expired") do
      JWT.decode(jwt_token, ed25519_private_key, JWT::Algorithm::EdDSA, verify: true, validate: true)
    end
  end

  it "EdDSA signatures are deterministic" do
    # EdDSA (unlike RSA-PSS) produces deterministic signatures
    # The same message and key will always produce the same signature
    payload = {"test" => "data"}

    token1 = JWT.encode(payload, ed25519_private_key, JWT::Algorithm::EdDSA)
    token2 = JWT.encode(payload, ed25519_private_key, JWT::Algorithm::EdDSA)

    # Tokens should be identical
    token1.should eq(token2)

    # Both should decode to the same payload
    decoded1, _ = JWT.decode(token1, ed25519_private_key, JWT::Algorithm::EdDSA, validate: false)
    decoded2, _ = JWT.decode(token2, ed25519_private_key, JWT::Algorithm::EdDSA, validate: false)
    decoded1["test"].should eq("data")
    decoded2["test"].should eq("data")
  end

  it "handles extended header fields correctly" do
    # EdDSA tokens may include additional header fields like kty, crv
    _payload, header = JWT.decode(jwt_token, verify: false, validate: false)

    # Standard JWT header fields
    header["alg"].should eq("EdDSA")
    header["typ"].should eq("JWT")

    # Extended fields from JWK specification
    header["kty"].should eq("EC")                      # Key Type: Elliptic Curve
    header["crv"].should eq("Ed25519")                 # Curve: Ed25519
    header["kid"].should eq("some-key-id-here-012345") # Key ID
  end
end
