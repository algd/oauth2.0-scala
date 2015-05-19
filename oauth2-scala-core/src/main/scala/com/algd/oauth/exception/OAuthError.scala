package com.algd.oauth.exception

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
  val errors = Map[Int, String](
    1 -> "grant_type not allowed for this client",
    2 -> "invalid user",
    3 -> "grant method not supported",
    4 -> "request method not supported",
    5 -> "missing grant_type parameter",
    6 -> "missing response_type parameter",
    7 -> "unknown authentication method",
    8 -> "refreshing token with different scope",
    9 -> "invalid refresh_token",
    10 -> "response_type not supported for this client",
    11 -> "incorrect redirect_uri parameter",
    12 -> "authorization code not found for this client",
    13 -> "invalid or expired token",
    14 -> "unknown token type",
    15 -> "insufficient scope for this protected resource",
    16 -> "missing access_token parameter",
    17 -> "authentication required for accessing protected resources",
    18 -> "unexpected use of authorization flow",
    19 -> "client must set at least one valid redirection uri",
    20 -> "missing refresh_token parameter",
    21 -> "given scope doesn't match requested scope")
  def ErrorDescription(id: Int) = Some(errors(id))
}

case class OAuthError(error: String, description: Option[String] = None) extends Exception