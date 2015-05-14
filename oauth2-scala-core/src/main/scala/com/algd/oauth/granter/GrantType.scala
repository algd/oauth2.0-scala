package com.algd.oauth.granter

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

  /**
   * Given a Grant Type returns its request handler
   *  @param grantType grant type contained in a request
   *  @return right request handler if exists
   */
  /*def apply(grantType: String)(implicit data: DataHandler): Option[Granter] = grantType match {
    case PASSWORD => Some(new PasswordGranter(data))
    case CLIENT_CREDENTIALS => Some(new ClientCredentialsGranter(data))
    case AUTHORIZATION_CODE => Some(new AuthorizationCodeGranter(data))
    case REFRESH_TOKEN => Some(new RefreshTokenGranter(data))
    case _ => None
  }*/
}