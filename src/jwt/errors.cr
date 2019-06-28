module JWT
  # Basic JWT exception.
  class Error < ::Exception; end

  # Is raised on attempt to use unsupported algorithm.
  class UnsupportedAlgorithmError < Error; end

  # raised when failed to decode token
  class DecodeError < Error; end

  # Is raised when failed to verify signature.
  class VerificationError < DecodeError; end

  # Is raised when signature is expired (see `exp` reserved claim name)
  class ExpiredSignatureError < DecodeError; end

  # Is raised when time hasn't reached nbf claim in the token.
  class ImmatureSignatureError < DecodeError; end

  # Is raised when 'aud' does not match.
  class InvalidAudienceError < DecodeError; end

  # Is raised when 'iss' does not match.
  class InvalidIssuerError < DecodeError; end

  # Is raised when 'sub' claim does not match.
  class InvalidSubjectError < DecodeError; end

  # Is raised when 'jti' claim is invalid.
  class InvalidJtiError < DecodeError; end
end
