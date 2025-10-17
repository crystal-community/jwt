require "../../spec_helper"

# This spec verifies compatibility with tokens from the l8w8jwt library
# Reference: https://github.com/GlitchedPolygons/l8w8jwt/blob/master/examples/es256k/decode.c
describe "ES256K decode compatibility" do
  # Token from l8w8jwt example
  jwt_token = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE2MTA1NzA1MTYsImV4cCI6MTYxMDU3MTExNiwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.pb4cAxFdnow3vfMeZQiGIUH4HzS89PAAScQALucogiw9i9588Kbw90ov8-BqUyQ4uJaCf5-N14zyCCeB4haFlQ"

  # secp256k1 keys from l8w8jwt example (PEM format)
  # Generated with: openssl ecparam -name secp256k1 -genkey -noout -out private.pem
  ecdsa_private_key = "-----BEGIN EC PRIVATE KEY-----\n" +
                      "MHQCAQEEIMRr0qJ5P1yLSjiVGVxrpSH2XHsEFbnLVG3IJ5UofWVWoAcGBSuBBAAK\n" +
                      "oUQDQgAEKDFMxQ2xpH+AabiiGGo+sXCeD52MYgufyE+AqMgsXbq9cD/TGFuqrCH3\n" +
                      "JncFWxLGamxuYQ9gdNZ9uJzk9pwgGw==\n" +
                      "-----END EC PRIVATE KEY-----"

  ecdsa_public_key = "-----BEGIN PUBLIC KEY-----\n" +
                     "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEKDFMxQ2xpH+AabiiGGo+sXCeD52MYguf\n" +
                     "yE+AqMgsXbq9cD/TGFuqrCH3JncFWxLGamxuYQ9gdNZ9uJzk9pwgGw==\n" +
                     "-----END PUBLIC KEY-----"

  it "can decode an ES256K token from l8w8jwt library" do
    # Decode without verification or validation (since token is expired)
    payload, header = JWT.decode(jwt_token, verify: false, validate: false)

    # Verify header
    header["alg"].should eq("ES256K")
    header["typ"].should eq("JWT")
    header["kty"].should eq("EC")
    header["crv"].should eq("secp256k1")
    header["kid"].should eq("some-key-id-here-012345")

    # Verify payload claims
    payload["iat"].should eq(1610570516)
    payload["exp"].should eq(1610571116)
    payload["sub"].should eq("Gordon Freeman")
    payload["iss"].should eq("Black Mesa")
    payload["aud"].should eq("Administrator")
    payload["ctx"].should eq("Unforseen Consequences")
    payload["age"].should eq(27)
    payload["size"].should eq(1.85)
    payload["alive"].should eq(true)
    payload["nulltest"].as_nil.should be_nil
  end

  it "can verify the ES256K signature with the public key" do
    # Verify signature (verify: true checks signature, validate: false skips expiry check)
    payload, _header = JWT.decode(jwt_token, ecdsa_public_key, JWT::Algorithm::ES256K, verify: true, validate: false)

    # Signature is valid, verify payload
    payload["sub"].should eq("Gordon Freeman")
    payload["iss"].should eq("Black Mesa")
    payload["aud"].should eq("Administrator")
    payload["ctx"].should eq("Unforseen Consequences")
  end

  it "can verify with the private key (derives public key)" do
    # ECDSA verification can work with private key (it extracts public key)
    payload, _header = JWT.decode(jwt_token, ecdsa_private_key, JWT::Algorithm::ES256K, verify: true, validate: false)
    payload["sub"].should eq("Gordon Freeman")
  end

  it "distinguishes between signature verification and claim validation" do
    # verify: true, validate: false -> checks signature but not expiry
    payload, _ = JWT.decode(jwt_token, ecdsa_public_key, JWT::Algorithm::ES256K, verify: true, validate: false)
    payload["sub"].should eq("Gordon Freeman")

    # verify: false, validate: false -> no checks at all
    payload, _ = JWT.decode(jwt_token, verify: false, validate: false)
    payload["sub"].should eq("Gordon Freeman")

    # verify: true, validate: true -> checks signature AND expiry (will fail)
    expect_raises(JWT::ExpiredSignatureError) do
      JWT.decode(jwt_token, ecdsa_public_key, JWT::Algorithm::ES256K, verify: true, validate: true)
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
    payload["iat"].as_i.should eq(1610570516) # 2021-01-13 19:35:16 UTC
    payload["exp"].as_i.should eq(1610571116) # 2021-01-13 19:45:16 UTC (10 minutes later)
  end

  it "token is expired and should fail exp validation" do
    # Token exp is 1610571116 (2021-01-13 19:45:16 UTC), which has passed
    expect_raises(JWT::ExpiredSignatureError, "Signature is expired") do
      JWT.decode(jwt_token, ecdsa_public_key, JWT::Algorithm::ES256K, verify: true, validate: true)
    end
  end

  it "handles extended header fields correctly" do
    # ES256K tokens may include additional header fields like kty, crv
    _payload, header = JWT.decode(jwt_token, verify: false, validate: false)

    # Standard JWT header fields
    header["alg"].should eq("ES256K")
    header["typ"].should eq("JWT")

    # Extended fields from JWK specification
    header["kty"].should eq("EC")                      # Key Type: Elliptic Curve
    header["crv"].should eq("secp256k1")               # Curve: secp256k1 (Bitcoin/Ethereum curve)
    header["kid"].should eq("some-key-id-here-012345") # Key ID
  end

  it "uses secp256k1 curve (different from NIST P-256)" do
    # IMPORTANT: secp256k1 (ES256K) and P-256 (ES256) are DIFFERENT curves!
    # They have the same key length but are completely different mathematically
    payload, header = JWT.decode(jwt_token, ecdsa_public_key, JWT::Algorithm::ES256K, verify: true, validate: false)

    # Verify this is secp256k1, not P-256
    header["crv"].should eq("secp256k1")
    header["alg"].should eq("ES256K")

    # secp256k1 is used by Bitcoin and Ethereum
    payload["sub"].should eq("Gordon Freeman")
  end

  it "signature is 64 bytes (32 bytes r + 32 bytes s)" do
    # Extract signature from token
    parts = jwt_token.split('.')
    signature = Base64.decode(parts[2])

    # secp256k1 with SHA-256 produces 64-byte signature
    signature.size.should eq(64)
  end
end
