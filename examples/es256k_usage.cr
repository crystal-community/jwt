require "../src/jwt"

puts "=== ES256K Algorithm (ECDSA with secp256k1) ==="
puts
puts "ES256K uses the secp256k1 elliptic curve, which is the same curve"
puts "used by Bitcoin and Ethereum. This makes it ideal for blockchain"
puts "and cryptocurrency applications."
puts

# Generate secp256k1 key pair
ec_key = OpenSSL::PKey::EC.generate_by_curve_name("secp256k1")
private_key = ec_key.to_pem
public_key = ec_key.public_key.to_pem

puts "Generated secp256k1 key pair"
puts

# Create a JWT with blockchain-related payload
payload = {
  "sub"     => "user@example.com",
  "chain"   => "ethereum",
  "address" => "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "iat"     => Time.utc.to_unix.to_i64,
  "exp"     => (Time.utc.to_unix + 3600).to_i64,
}

puts "Encoding JWT with ES256K..."
token = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)
puts "Token: #{token[0..80]}..."
puts

# Decode and verify
puts "Decoding and verifying JWT..."
decoded_payload, decoded_header = JWT.decode(token, public_key, JWT::Algorithm::ES256K)

puts "Header:"
puts "  Algorithm: #{decoded_header["alg"]}"
puts "  Type: #{decoded_header["typ"]}"
puts

puts "Payload:"
puts "  Subject: #{decoded_payload["sub"]}"
puts "  Chain: #{decoded_payload["chain"]}"
puts "  Address: #{decoded_payload["address"]}"
puts

# Demonstrate signature randomness
puts "=== ECDSA Signature Randomness ==="
puts
token1 = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)
token2 = JWT.encode(payload, private_key, JWT::Algorithm::ES256K)

puts "Token 1: #{token1[0..80]}..."
puts "Token 2: #{token2[0..80]}..."
puts "Tokens are different: #{token1 != token2}"
puts "Both signatures are valid!"
puts

# Verify both tokens
JWT.decode(token1, public_key, JWT::Algorithm::ES256K)
JWT.decode(token2, public_key, JWT::Algorithm::ES256K)
puts "✓ Both tokens verified successfully"
puts

# Show signature size
puts "=== Signature Details ==="
parts = token.split('.')
signature = Base64.decode(parts[2])
puts "Signature size: #{signature.size} bytes"
puts "  (32 bytes for r component + 32 bytes for s component)"
puts

puts "=== Blockchain Use Cases ==="
puts
puts "ES256K is particularly useful for:"
puts "  • Bitcoin and Ethereum authentication"
puts "  • Blockchain wallet integrations"
puts "  • Cryptocurrency payment systems"
puts "  • Web3 applications"
puts "  • Decentralized identity (DID)"
puts
puts "The secp256k1 curve is optimized for efficient signature"
puts "verification and is widely supported in blockchain ecosystems."
