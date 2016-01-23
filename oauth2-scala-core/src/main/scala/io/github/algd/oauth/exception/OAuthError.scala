package io.github.algd.oauth.exception

/**
 * This object contains all the OAuth2 errors.
 */
object OAuthError {
  // Standard errors
  val INVALID_REQUEST = "invalid_request"
  val INVALID_CLIENT = "invalid_client"
  val INVALID_GRANT = "invalid_grant"
  val UNAUTHORIZED_CLIENT = "unauthorized_client"
  val ACCESS_DENIED = "access_denied"
  val UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
  val UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
  val INVALID_SCOPE = "invalid_scope"
  val SERVER_ERROR = "server_error"
  val TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"

  // Bearer standard errors
  val INSUFFICIENT_SCOPE = "insufficient_scope"
  val INVALID_TOKEN = "invalid_token"

  // Other errors
  val UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"

  // Error descriptions
  val GRANT_NOT_ALLOWED = "grant_type not allowed for this client"
  val INVALID_USER = "invalid user"
  val UNSUPPORTED_GRANT = "grant method not supported"
  val UNSUPPORTED_REQUEST = "request method not supported"
  val MISSING_GRANT_TYPE = "missing grant_type parameter"
  val MISSING_RESPONSE_TYPE = "missing response_type parameter"
  val UNKNOWN_AUTH_METHOD = "unknown authentication method"
  val DIFFERENT_REFRESH_SCOPE = "refreshing token with different scope"
  val INVALID_REFRESH_TOKEN = "invalid refresh_token"
  val UNSUPPORTED_RESPONSE = "response_type not supported for this client"
  val INCORRECT_REDIRECT_URI = "incorrect redirect_uri parameter"
  val AUTH_CODE_NOT_FOUND = "authorization code not found for this client"
  val INVALID_OR_EXPIRED_TOKEN = "invalid or expired token"
  val UNKNOWN_TOKEN_TYPE = "unknown token type"
  val PROTECTED_RESOURCE = "insufficient scope for this protected resource"
  val MISSING_ACCESS_TOKEN = "missing access_token parameter"
  val AUTH_REQUIRED = "authentication required for accessing protected resources"
  val UNEXPECTED_USE = "unexpected use of authorization flow"
  val REDIRECT_URI_REQUIRED = "client must set at least one valid redirection uri"
  val MISSING_REFRESH_TOKEN = "missing refresh_token parameter"
  val DIFFERENT_SCOPE = "given scope doesn't match requested scope"
}

/**
 * OAuth2 exception
 * @param error error type
 * @param description error description
 * @param state request state parameter
 */
case class OAuthError(
  error: String,
  description: Option[String] = None,
  state: Option[String] = None) extends Exception(error + ": " + description.mkString(""))