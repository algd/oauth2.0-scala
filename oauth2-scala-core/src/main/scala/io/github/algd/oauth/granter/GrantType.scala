package io.github.algd.oauth.granter

/**
 *  Contains GrantType data
 */
object GrantType {
  /** Keyword for Resource Owner Password Credentials Grant */
  val PASSWORD = "password"
  /** Keyword for Client Credentials Grant */
  val CLIENT_CREDENTIALS = "client_credentials"
  /** Keyword for Authorization Code Grant */
  val AUTHORIZATION_CODE = "authorization_code"
  /** Keyword for Refreshing an Access Token */
  val REFRESH_TOKEN = "refresh_token"
  /** Keyword for Implicit Grant */
  val IMPLICIT = "implicit"
}