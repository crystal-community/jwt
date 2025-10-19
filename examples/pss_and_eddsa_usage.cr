require "../src/jwt"

puts "=== RSA-PSS Algorithms (PS256, PS384, PS512) ==="
puts

# Generate RSA keys for PS256/PS384 (1024-bit is minimum, but 2048+ recommended)
rsa_key = OpenSSL::PKey::RSA.new(2048)
private_key = rsa_key.to_pem
public_key = rsa_key.public_key.to_pem

payload = {"user" => "john_doe", "exp" => (Time.utc.to_unix + 3600).to_i64}

# PS256 Example
puts "PS256 (RSA-PSS with SHA-256):"
token_ps256 = JWT.encode(payload, private_key, JWT::Algorithm::PS256)
puts "Token: #{token_ps256[0..50]}..."
decoded_ps256 = JWT.decode(token_ps256, public_key, JWT::Algorithm::PS256)
puts "Decoded: #{decoded_ps256[0]}"
puts

# PS384 Example
puts "PS384 (RSA-PSS with SHA-384):"
token_ps384 = JWT.encode(payload, private_key, JWT::Algorithm::PS384)
puts "Token: #{token_ps384[0..50]}..."
decoded_ps384 = JWT.decode(token_ps384, public_key, JWT::Algorithm::PS384)
puts "Decoded: #{decoded_ps384[0]}"
puts

# PS512 Example (requires 2048-bit key minimum)
puts "PS512 (RSA-PSS with SHA-512):"
token_ps512 = JWT.encode(payload, private_key, JWT::Algorithm::PS512)
puts "Token: #{token_ps512[0..50]}..."
decoded_ps512 = JWT.decode(token_ps512, public_key, JWT::Algorithm::PS512)
puts "Decoded: #{decoded_ps512[0]}"
puts

puts "Note: RSA-PSS uses random salt, so tokens are different each time:"
token1 = JWT.encode(payload, private_key, JWT::Algorithm::PS256)
token2 = JWT.encode(payload, private_key, JWT::Algorithm::PS256)
puts "Token 1: #{token1[0..50]}..."
puts "Token 2: #{token2[0..50]}..."
puts "Same content: #{token1 == token2 ? "Yes" : "No"}"
puts

puts "=== EdDSA (Ed25519) Algorithm ==="
puts

# Generate Ed25519 key (32 bytes)
ed_private_key_bytes = Bytes[
  0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
  0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
  0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
  0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
]
ed_private_key = ed_private_key_bytes.hexstring

puts "EdDSA (Edwards-curve Digital Signature Algorithm):"
token_eddsa = JWT.encode(payload, ed_private_key, JWT::Algorithm::EdDSA)
puts "Token: #{token_eddsa[0..50]}..."
decoded_eddsa = JWT.decode(token_eddsa, ed_private_key, JWT::Algorithm::EdDSA)
puts "Decoded: #{decoded_eddsa[0]}"
puts

puts "Note: EdDSA signatures are deterministic, so tokens are identical:"
token1 = JWT.encode(payload, ed_private_key, JWT::Algorithm::EdDSA)
token2 = JWT.encode(payload, ed_private_key, JWT::Algorithm::EdDSA)
puts "Token 1: #{token1[0..50]}..."
puts "Token 2: #{token2[0..50]}..."
puts "Same content: #{token1 == token2 ? "Yes" : "No"}"
