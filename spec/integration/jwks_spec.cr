require "../spec_helper"

describe JWT::JWKS do
  # Load test fixtures
  sample_rsa_pubkey_pem = File.read("./spec/fixtures/pubkey.pem")
  sample_rsa_private_pem = File.read("./spec/fixtures/private.pem")
  sample_jwks_json = File.read("./spec/fixtures/jwk-pubkey.json")

  # Parse JWKS
  jwks = JWT::JWKS::JWKSet.from_json(sample_jwks_json)
  sample_kid = jwks.keys.first.kid

  # Sample issuer and JWKS URI
  sample_issuer = "https://example.com"
  sample_jwks_uri = "#{sample_issuer}/keys"

  # Create sample tokens
  sample_payload = {
    "sub"   => "1234567890",
    "name"  => "John Doe",
    "iat"   => Time.utc.to_unix,
    "exp"   => (Time.utc + 1.hour).to_unix,
    "iss"   => sample_issuer,
    "aud"   => "test-app",
    "scp"   => ["read", "write"],
    "roles" => ["admin"],
  }

  sample_token = JWT.encode(sample_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid)

  describe "JWK" do
    it "parses RSA JWK from JSON" do
      jwk = jwks.keys.first
      jwk.kid.should eq("bed7f3ea-d9c0-4e91-8455-d65604a4b030")
      jwk.kty.should eq("RSA")
      jwk.n.should_not be_nil
      jwk.e.should_not be_nil
    end

    it "converts RSA JWK to PEM" do
      jwk = jwks.keys.first
      pem = jwk.to_pem
      pem.should contain("BEGIN PUBLIC KEY")
      pem.should contain("END PUBLIC KEY")
      pem.chomp.should eq(sample_rsa_pubkey_pem.chomp)
    end

    it "raises error for unsupported key type" do
      jwk = JWT::JWKS::JWK.from_json({
        kid: "test",
        kty: "UNSUPPORTED",
        n:   "test",
        e:   "test",
      }.to_json)

      expect_raises(JWT::UnsupportedAlgorithmError) do
        jwk.to_pem
      end
    end

    it "raises error for missing RSA components" do
      jwk = JWT::JWKS::JWK.from_json({
        kid: "test",
        kty: "RSA",
      }.to_json)

      expect_raises(JWT::DecodeError, /Missing RSA key components/) do
        jwk.to_pem
      end
    end
  end

  describe "OIDC Metadata" do
    it "parses OIDC metadata from JSON" do
      metadata_json = {
        issuer:                                sample_issuer,
        jwks_uri:                              sample_jwks_uri,
        authorization_endpoint:                "#{sample_issuer}/authorize",
        token_endpoint:                        "#{sample_issuer}/token",
        userinfo_endpoint:                     "#{sample_issuer}/userinfo",
        end_session_endpoint:                  "#{sample_issuer}/logout",
        response_types_supported:              ["code", "token"],
        subject_types_supported:               ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      }.to_json

      metadata = JWT::JWKS::OIDCMetadata.from_json(metadata_json)
      metadata.issuer.should eq(sample_issuer)
      metadata.jwks_uri.should eq(sample_jwks_uri)
      metadata.authorization_endpoint.should eq("#{sample_issuer}/authorize")
    end
  end

  describe "JWKS class" do
    describe "initialization" do
      it "creates JWKS validator without local keys" do
        validator = JWT::JWKS.new
        validator.local_keys.should be_nil
        validator.local_algorithm.should be_nil
        validator.cache_ttl.should eq(JWT::JWKS::DEFAULT_CACHE_TTL)
      end

      it "creates JWKS validator with local keys" do
        local_keys = {"key1" => "secret"}
        validator = JWT::JWKS.new(
          local_keys: local_keys,
          local_algorithm: JWT::Algorithm::HS256
        )
        validator.local_keys.should eq(local_keys)
        validator.local_algorithm.should eq(JWT::Algorithm::HS256)
      end

      it "creates JWKS validator with custom cache TTL" do
        validator = JWT::JWKS.new(cache_ttl: 5.minutes)
        validator.cache_ttl.should eq(5.minutes)
      end
    end

    describe "local validation" do
      it "validates JWT with local keys" do
        local_keys = {"local_kid" => "my_secret_key"}
        validator = JWT::JWKS.new(
          local_keys: local_keys,
          local_algorithm: JWT::Algorithm::HS256
        )

        payload = {
          "sub" => "user123",
          "exp" => (Time.utc + 1.hour).to_unix,
        }

        token = JWT.encode(payload, "my_secret_key", JWT::Algorithm::HS256, kid: "local_kid")

        result = validator.validate(token)
        result.should_not be_nil
        result.as(JSON::Any)["sub"].as_s.should eq("user123")
      end

      it "returns nil for invalid local token" do
        local_keys = {"local_kid" => "my_secret_key"}
        validator = JWT::JWKS.new(
          local_keys: local_keys,
          local_algorithm: JWT::Algorithm::HS256
        )

        payload = {
          "sub" => "user123",
          "exp" => (Time.utc + 1.hour).to_unix,
        }

        # Create token with different key
        token = JWT.encode(payload, "wrong_key", JWT::Algorithm::HS256, kid: "local_kid")

        result = validator.validate(token)
        result.should be_nil
      end

      it "validates local token with scope checking" do
        local_keys = {"local_kid" => "my_secret_key"}
        validator = JWT::JWKS.new(
          local_keys: local_keys,
          local_algorithm: JWT::Algorithm::HS256
        )

        payload = {
          "sub" => "user123",
          "exp" => (Time.utc + 1.hour).to_unix,
          "scp" => ["read"],
        }

        token = JWT.encode(payload, "my_secret_key", JWT::Algorithm::HS256, kid: "local_kid")

        result = validator.validate(token)
        result.should_not be_nil

        scopes = JWT::JWKS.extract_scopes(result.as(JSON::Any))
        scopes.should contain("read")
      end
    end

    describe "JWKS validation with mocked HTTP" do
      it "validates token using JWKS" do
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new
        result = validator.validate(sample_token, issuer: sample_issuer, audience: "test-app")

        result.should_not be_nil
        result.as(JSON::Any)["name"].as_s.should eq("John Doe")
        result.as(JSON::Any)["iss"].as_s.should eq(sample_issuer)
      end

      it "validates token and checks scopes" do
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new

        result = validator.validate(sample_token, issuer: sample_issuer, audience: "test-app")

        result.should_not be_nil
        result.as(JSON::Any)["name"].as_s.should eq("John Doe")

        # Check scopes after validation
        scopes = JWT::JWKS.extract_scopes(result.as(JSON::Any))
        scopes.should contain("read")
        scopes.should contain("write")
      end

      it "validates token and checks roles" do
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new

        result = validator.validate(sample_token, issuer: sample_issuer, audience: "test-app")

        result.should_not be_nil
        result.as(JSON::Any)["name"].as_s.should eq("John Doe")

        # Check roles after validation
        roles = JWT::JWKS.extract_roles(result.as(JSON::Any))
        roles.should contain("admin")
      end

      it "returns nil for expired token" do
        expired_payload = sample_payload.merge({
          "exp" => (Time.utc - 1.hour).to_unix,
        })
        expired_token = JWT.encode(expired_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid)

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new
        result = validator.validate(expired_token, issuer: sample_issuer, audience: "test-app")

        result.should be_nil
      end

      it "validates expired token when validation disabled" do
        expired_payload = sample_payload.merge({
          "exp" => (Time.utc - 1.hour).to_unix,
        })
        expired_token = JWT.encode(expired_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid)

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new
        result = validator.validate(expired_token, issuer: sample_issuer, audience: "test-app", validate_claims: false)

        result.should_not be_nil
        result.as(JSON::Any)["name"].as_s.should eq("John Doe")
      end

      it "caches OIDC metadata" do
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        validator = JWT::JWKS.new

        # First fetch
        metadata1 = validator.fetch_oidc_metadata(sample_issuer)
        metadata1.issuer.should eq(sample_issuer)

        # Second fetch should use cache
        metadata2 = validator.fetch_oidc_metadata(sample_issuer)
        metadata2.issuer.should eq(sample_issuer)
      end

      it "caches JWKS" do
        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new

        # First fetch
        jwks1 = validator.fetch_jwks(sample_jwks_uri)
        jwks1.keys.size.should be > 0

        # Second fetch should use cache
        jwks2 = validator.fetch_jwks(sample_jwks_uri)
        jwks2.keys.size.should be > 0
      end

      it "clears cache" do
        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new

        # Fetch and cache
        validator.fetch_jwks(sample_jwks_uri)

        # Clear cache
        validator.clear_cache

        # Should fetch again
        jwks = validator.fetch_jwks(sample_jwks_uri)
        jwks.keys.size.should be > 0
      end
    end

    describe "scope and role validation" do
      it "validates scopes from scp claim (Entra format)" do
        payload = JSON.parse({
          scp: ["read", "write", "delete"],
        }.to_json)

        JWT::JWKS.validate_scopes(payload, ["read", "write"]).should be_true
        JWT::JWKS.validate_scopes(payload, ["read", "admin"]).should be_false
      end

      it "validates scopes from scope claim (standard format)" do
        payload = JSON.parse({
          scope: "read write delete",
        }.to_json)

        JWT::JWKS.validate_scopes(payload, ["read", "write"]).should be_true
        JWT::JWKS.validate_scopes(payload, ["read", "admin"]).should be_false
      end

      it "extracts empty scopes when not present" do
        payload = JSON.parse({
          sub: "user123",
        }.to_json)

        scopes = JWT::JWKS.extract_scopes(payload)
        scopes.should be_empty
      end

      it "validates roles" do
        payload = JSON.parse({
          roles: ["admin", "user"],
        }.to_json)

        JWT::JWKS.validate_roles(payload, ["admin"]).should be_true
        JWT::JWKS.validate_roles(payload, ["admin", "superadmin"]).should be_false
      end

      it "extracts empty roles when not present" do
        payload = JSON.parse({
          sub: "user123",
        }.to_json)

        roles = JWT::JWKS.extract_roles(payload)
        roles.should be_empty
      end
    end

    describe "error handling" do
      it "returns nil when OIDC metadata fetch fails" do
        WebMock.reset
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 404, body: "Not Found")

        # Create validator without local keys so it tries JWKS
        validator = JWT::JWKS.new
        # Clear cache to ensure fresh fetch
        validator.clear_cache
        result = validator.validate(sample_token, issuer: sample_issuer)

        result.should be_nil
      end

      it "returns nil when JWKS fetch fails" do
        WebMock.reset
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 404, body: "Not Found")

        # Create validator without local keys so it tries JWKS
        validator = JWT::JWKS.new
        # Clear cache to ensure fresh fetch
        validator.clear_cache
        result = validator.validate(sample_token, issuer: sample_issuer)

        result.should be_nil
      end

      it "returns nil when kid not found in JWKS" do
        wrong_kid_payload = sample_payload
        wrong_token = JWT.encode(wrong_kid_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: "wrong_kid")

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new
        result = validator.validate(wrong_token, issuer: sample_issuer)

        result.should be_nil
      end

      it "returns nil when signature verification fails" do
        # Create a different key pair
        wrong_private_key = OpenSSL::PKey::RSA.new(2048).to_pem
        wrong_token = JWT.encode(sample_payload, wrong_private_key, JWT::Algorithm::RS256, kid: sample_kid)

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new
        result = validator.validate(wrong_token, issuer: sample_issuer)

        result.should be_nil
      end

      it "returns nil when audience doesn't match" do
        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: sample_jwks_uri,
          }.to_json)

        WebMock.stub(:get, sample_jwks_uri)
          .to_return(status: 200, body: sample_jwks_json)

        validator = JWT::JWKS.new
        result = validator.validate(sample_token, issuer: sample_issuer, audience: "wrong-app")

        result.should be_nil
      end

      it "returns nil when issuer doesn't match" do
        wrong_issuer = "https://wrong-issuer.com"

        WebMock.stub(:get, "#{wrong_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   wrong_issuer,
            jwks_uri: "#{wrong_issuer}/keys",
          }.to_json)

        WebMock.stub(:get, "#{wrong_issuer}/keys")
          .to_return(status: 200, body: sample_jwks_json)

        # Create validator without local keys so it tries JWKS
        validator = JWT::JWKS.new
        result = validator.validate(sample_token, issuer: wrong_issuer, audience: "test-app")

        result.should be_nil
      end
    end
  end
end
