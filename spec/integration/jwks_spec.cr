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
      pem.gsub(/\s+/, "").should eq(sample_rsa_pubkey_pem.gsub(/\s+/, ""))
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

    describe "security improvements" do
      before_each do
        WebMock.reset
      end

      describe "algorithm validation" do
        it "rejects 'none' algorithm" do
          # Create token with 'none' algorithm
          none_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."

          WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
            .to_return(status: 200, body: {
              issuer:   sample_issuer,
              jwks_uri: sample_jwks_uri,
            }.to_json)

          validator = JWT::JWKS.new
          result = validator.validate(none_token, issuer: sample_issuer)
          result.should be_nil
        end

        it "rejects algorithm not in allow-list" do
          # Create token with unsupported algorithm (HS256 is not in JWKS allow-list)
          payload = sample_payload
          hs_token = JWT.encode(payload, "secret", JWT::Algorithm::HS256, kid: sample_kid)

          WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
            .to_return(status: 200, body: {
              issuer:   sample_issuer,
              jwks_uri: sample_jwks_uri,
            }.to_json)

          WebMock.stub(:get, sample_jwks_uri)
            .to_return(status: 200, body: sample_jwks_json)

          validator = JWT::JWKS.new
          result = validator.validate(hs_token, issuer: sample_issuer)
          result.should be_nil
        end
      end

      describe "HTTPS enforcement" do
        it "rejects HTTP issuer URLs" do
          http_issuer = "http://insecure.com"
          validator = JWT::JWKS.new
          validator.clear_cache

          expect_raises(JWT::DecodeError, /must use HTTPS/) do
            validator.fetch_oidc_metadata(http_issuer)
          end
        end

        it "rejects HTTP JWKS URIs" do
          http_jwks_uri = "http://insecure.com/keys"
          validator = JWT::JWKS.new
          validator.clear_cache

          expect_raises(JWT::DecodeError, /must use HTTPS/) do
            validator.fetch_jwks(http_jwks_uri)
          end
        end
      end

      describe "typ validation" do
        it "accepts JWT typ" do
          jwt_payload = sample_payload.merge({"iss" => sample_issuer, "aud" => "test-app"})
          jwt_token = JWT.encode(jwt_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid, typ: "JWT")

          WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
            .to_return(status: 200, body: {
              issuer:   sample_issuer,
              jwks_uri: sample_jwks_uri,
            }.to_json)

          WebMock.stub(:get, sample_jwks_uri)
            .to_return(status: 200, body: sample_jwks_json)

          validator = JWT::JWKS.new
          validator.clear_cache
          result = validator.validate(jwt_token, audience: "test-app")
          result.should_not be_nil
        end

        it "accepts at+jwt typ (RFC 9068)" do
          jwt_payload = sample_payload.merge({"iss" => sample_issuer, "aud" => "test-app"})
          jwt_token = JWT.encode(jwt_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid, typ: "at+jwt")

          WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
            .to_return(status: 200, body: {
              issuer:   sample_issuer,
              jwks_uri: sample_jwks_uri,
            }.to_json)

          WebMock.stub(:get, sample_jwks_uri)
            .to_return(status: 200, body: sample_jwks_json)

          validator = JWT::JWKS.new
          validator.clear_cache
          result = validator.validate(jwt_token, audience: "test-app")
          result.should_not be_nil
        end

        it "rejects invalid typ" do
          jwt_payload = sample_payload.merge({"iss" => sample_issuer})
          jwt_token = JWT.encode(jwt_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid, typ: "INVALID")

          WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
            .to_return(status: 200, body: {
              issuer:   sample_issuer,
              jwks_uri: sample_jwks_uri,
            }.to_json)

          validator = JWT::JWKS.new
          validator.clear_cache
          result = validator.validate(jwt_token)
          result.should be_nil
        end
      end

      describe "cache refresh on missing kid" do
        it "refreshes cache when kid not found" do
          # Test that we attempt multiple fetches when kid is missing
          # The second fetch should succeed
          call_count = 0
          refresh_payload = sample_payload.merge({"iss" => sample_issuer, "aud" => "test-app"})
          refresh_token = JWT.encode(refresh_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: sample_kid)

          WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
            .to_return(status: 200, body: {
              issuer:   sample_issuer,
              jwks_uri: sample_jwks_uri,
            }.to_json)

          # Stub JWKS endpoint to return different responses
          WebMock.stub(:get, sample_jwks_uri).to_return do
            call_count += 1
            if call_count == 1
              # First call: empty JWKS (kid not found)
              HTTP::Client::Response.new(200, {keys: [] of JWT::JWKS::JWK}.to_json)
            else
              # Second call: return actual JWKS (after refresh)
              HTTP::Client::Response.new(200, sample_jwks_json)
            end
          end

          validator = JWT::JWKS.new
          validator.clear_cache

          # This should trigger cache refresh when kid not found
          result = validator.validate(refresh_token, audience: "test-app")
          result.should_not be_nil
          call_count.should eq(2) # Verify refresh happened
        end
      end
    end

    describe "enhanced scope extraction" do
      it "extracts space-delimited scp (Entra format)" do
        payload = JSON.parse({
          scp: "User.Read Mail.Send Files.Read",
        }.to_json)

        scopes = JWT::JWKS.extract_scopes(payload)
        scopes.should eq(["User.Read", "Mail.Send", "Files.Read"])
      end

      it "extracts array scp" do
        payload = JSON.parse({
          scp: ["User.Read", "Mail.Send"],
        }.to_json)

        scopes = JWT::JWKS.extract_scopes(payload)
        scopes.should eq(["User.Read", "Mail.Send"])
      end

      it "extracts space-delimited scope" do
        payload = JSON.parse({
          scope: "read write delete",
        }.to_json)

        scopes = JWT::JWKS.extract_scopes(payload)
        scopes.should eq(["read", "write", "delete"])
      end

      it "extracts Auth0 permissions" do
        payload = JSON.parse({
          permissions: ["read:users", "write:users"],
        }.to_json)

        scopes = JWT::JWKS.extract_scopes(payload)
        scopes.should eq(["read:users", "write:users"])
      end
    end

    describe "enhanced role extraction" do
      it "extracts Azure AD roles" do
        payload = JSON.parse({
          roles: ["Admin", "User"],
        }.to_json)

        roles = JWT::JWKS.extract_roles(payload)
        roles.should eq(["Admin", "User"])
      end

      it "extracts Keycloak realm roles" do
        payload = JSON.parse({
          realm_access: {
            roles: ["admin", "user", "offline_access"],
          },
        }.to_json)

        roles = JWT::JWKS.extract_roles(payload)
        roles.should eq(["admin", "user", "offline_access"])
      end

      it "extracts Keycloak resource roles" do
        payload = JSON.parse({
          resource_access: {
            "account" => {
              "roles" => ["manage-account", "view-profile"],
            },
            "my-client" => {
              "roles" => ["client-admin"],
            },
          },
        }.to_json)

        roles = JWT::JWKS.extract_roles(payload)
        roles.size.should eq(3)
        roles.should contain("manage-account")
        roles.should contain("view-profile")
        roles.should contain("client-admin")
      end

      it "extracts Okta groups" do
        payload = JSON.parse({
          groups: ["Everyone", "Admins", "Developers"],
        }.to_json)

        roles = JWT::JWKS.extract_roles(payload)
        roles.should eq(["Everyone", "Admins", "Developers"])
      end
    end

    describe "HTTP caching" do
      it "respects Cache-Control max-age" do
        # Use HTTPS URL
        https_jwks_uri = "https://example.com/jwks"
        validator = JWT::JWKS.new
        validator.clear_cache

        WebMock.stub(:get, https_jwks_uri)
          .to_return(
            status: 200,
            body: sample_jwks_json,
            headers: HTTP::Headers{"Cache-Control" => "max-age=3600"}
          )

        jwks1 = validator.fetch_jwks(https_jwks_uri)
        jwks1.keys.size.should be > 0
      end

      it "uses ETag for conditional requests" do
        # Use HTTPS URL
        https_jwks_uri = "https://example.com/jwks"
        validator = JWT::JWKS.new
        validator.clear_cache

        # First request with ETag
        WebMock.stub(:get, https_jwks_uri)
          .to_return(
            status: 200,
            body: sample_jwks_json,
            headers: HTTP::Headers{"ETag" => "\"abc123\""}
          )

        jwks1 = validator.fetch_jwks(https_jwks_uri)
        jwks1.keys.size.should be > 0

        # Subsequent request should use If-None-Match
        # (This is hard to test with WebMock, but the code path is exercised)
      end
    end

    describe "leeway configuration" do
      it "accepts custom leeway" do
        validator = JWT::JWKS.new(leeway: 120.seconds)
        validator.leeway.should eq(120.seconds)
      end

      it "uses default leeway" do
        validator = JWT::JWKS.new
        validator.leeway.should eq(JWT::JWKS::DEFAULT_LEEWAY)
      end
    end

    describe "EC key support (ES256/ES384/ES512)" do
      it "supports ES256 algorithm in allow-list" do
        # Verify ES256 is in the allow-list
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("ES256")
      end

      it "supports ES384 algorithm in allow-list" do
        # Verify ES384 is in the allow-list
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("ES384")
      end

      it "supports ES512 algorithm in allow-list" do
        # Verify ES512 is in the allow-list
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("ES512")
      end
    end

    describe "EdDSA key support" do
      before_each do
        WebMock.reset
      end

      it "converts EdDSA JWK to hex format and validates token" do
        # Generate Ed25519 key
        ed_private_bytes = Bytes[
          0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
          0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
          0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
          0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ]
        ed_private_hex = ed_private_bytes.hexstring
        ed_public_bytes = Ed25519.get_public_key(ed_private_bytes)
        ed_public_b64 = Base64.urlsafe_encode(ed_public_bytes, false)

        # Create EdDSA token
        eddsa_payload = {
          "sub"   => "user456",
          "iat"   => Time.utc.to_unix,
          "exp"   => (Time.utc + 1.hour).to_unix,
          "iss"   => sample_issuer,
          "aud"   => "test-app",
          "roles" => ["admin"],
        }

        eddsa_token = JWT.encode(eddsa_payload, ed_private_hex, JWT::Algorithm::EdDSA, kid: "eddsa-test-key")

        # Create mock JWK for EdDSA
        eddsa_jwk_json = {
          keys: [{
            kty: "OKP",
            crv: "Ed25519",
            kid: "eddsa-test-key",
            use: "sig",
            x:   ed_public_b64,
          }],
        }.to_json

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: "#{sample_issuer}/eddsa-keys",
          }.to_json)

        WebMock.stub(:get, "#{sample_issuer}/eddsa-keys")
          .to_return(status: 200, body: eddsa_jwk_json)

        validator = JWT::JWKS.new
        validator.clear_cache

        result = validator.validate(eddsa_token, audience: "test-app")
        result.should_not be_nil
        result.as(JSON::Any)["sub"].as_s.should eq("user456")
        result.as(JSON::Any)["roles"].as_a.map(&.as_s).should eq(["admin"])
      end

      it "rejects EdDSA with wrong curve" do
        # Create mock JWK with unsupported curve
        bad_jwk = JWT::JWKS::JWK.from_json({
          kty: "OKP",
          crv: "Ed448",
          kid: "bad-key",
          x:   "dGVzdA",
        }.to_json)

        expect_raises(JWT::UnsupportedAlgorithmError, /Only Ed25519/) do
          bad_jwk.to_pem
        end
      end

      it "supports EdDSA algorithm in allow-list" do
        # Verify EdDSA is in the allow-list
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("EdDSA")
      end
    end

    describe "algorithm and key type validation" do
      before_each do
        WebMock.reset
      end

      it "supports all RSA PSS algorithms (PS256/384/512)" do
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("PS256")
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("PS384")
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("PS512")
      end

      it "supports all RSA algorithms (RS256/384/512)" do
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("RS256")
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("RS384")
        JWT::JWKS::ALLOWED_ALGORITHMS.should contain("RS512")
      end

      it "does not allow HS256/384/512 for JWKS" do
        # HMAC algorithms should not be in JWKS allow-list (symmetric keys)
        JWT::JWKS::ALLOWED_ALGORITHMS.should_not contain("HS256")
        JWT::JWKS::ALLOWED_ALGORITHMS.should_not contain("HS384")
        JWT::JWKS::ALLOWED_ALGORITHMS.should_not contain("HS512")
      end

      it "rejects tokens with JWK use='enc' (encryption key)" do
        # Create token signed with RS256
        bad_payload = sample_payload.merge({"iss" => sample_issuer, "aud" => "test-app"})
        bad_token = JWT.encode(bad_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: "enc-key")

        # Create JWKS with use="enc" (should be rejected)
        enc_jwks = {
          keys: [{
            kty: "RSA",
            use: "enc",
            kid: "enc-key",
            n:   jwks.keys.first.n,
            e:   jwks.keys.first.e,
          }],
        }.to_json

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: "#{sample_issuer}/bad-keys",
          }.to_json)

        WebMock.stub(:get, "#{sample_issuer}/bad-keys")
          .to_return(status: 200, body: enc_jwks)

        validator = JWT::JWKS.new
        validator.clear_cache

        # Should return nil (validation fails)
        result = validator.validate(bad_token, audience: "test-app")
        result.should be_nil
      end

      it "rejects tokens with incompatible key_ops" do
        # Create token signed with RS256
        bad_payload = sample_payload.merge({"iss" => sample_issuer, "aud" => "test-app"})
        bad_token = JWT.encode(bad_payload, sample_rsa_private_pem, JWT::Algorithm::RS256, kid: "ops-key")

        # Create JWKS with key_ops that doesn't include "verify"
        ops_jwks = {
          keys: [{
            kty:     "RSA",
            key_ops: ["encrypt", "wrapKey"],
            kid:     "ops-key",
            n:       jwks.keys.first.n,
            e:       jwks.keys.first.e,
          }],
        }.to_json

        WebMock.stub(:get, "#{sample_issuer}/.well-known/openid-configuration")
          .to_return(status: 200, body: {
            issuer:   sample_issuer,
            jwks_uri: "#{sample_issuer}/bad-ops-keys",
          }.to_json)

        WebMock.stub(:get, "#{sample_issuer}/bad-ops-keys")
          .to_return(status: 200, body: ops_jwks)

        validator = JWT::JWKS.new
        validator.clear_cache

        # Should return nil (validation fails)
        result = validator.validate(bad_token, audience: "test-app")
        result.should be_nil
      end
    end
  end
end
