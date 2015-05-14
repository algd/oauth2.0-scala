package com.algd.oauth.authorizer

import com.algd.oauth.granter.GrantType

/**
 *  Contains ResponseType data
 */
object ResponseType {
  /** Keyword for Authorization Code Response */
  val CODE = "code"
  /** Keyword for Implicit Grant Response */
  val TOKEN = "token"

  /**
   *  Given a response type returns its request handler
   *  @param responseType response type contained in a request
   *  @return right request handler
   */
  /*def apply(responseType: String)(implicit data: DataHandler) = responseType match {
    case CODE => Some(new CodeAuthorizer(data))
    case TOKEN => Some(new ImplicitAuthorizer(data))
    case _ => None
  }*/

  /**
   *  Given a response type returns its grant type
   *  @param responseType response type contained in a request
   *  @return grant type
   */
  def grantTypeFor(responseType: String) = responseType match {
    case CODE => Some(GrantType.AUTHORIZATION_CODE)
    case TOKEN => Some(GrantType.IMPLICIT)
    case _ => None
  }
}