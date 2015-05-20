package com.algd.oauth.authorizer

import java.net.URLEncoder

import com.algd.oauth.data.model.UriResponse
import com.algd.oauth.granter.GrantType
import com.algd.oauth.utils.OAuthParams

/**
 *  Contains ResponseType data
 */
object ResponseType {
  /** Keyword for Authorization Code Response */
  val CODE = "code"
  /** Keyword for Implicit Grant Response */
  val TOKEN = "token"

  /**
   *  Given a response type returns its grant type
   *  @param responseType response type contained in a request
   *  @return grant type
   */
  def grantTypeFor(responseType: String) = responseType match {
    case CODE => GrantType.AUTHORIZATION_CODE
    case TOKEN => GrantType.IMPLICIT
    case other => other
  }

  def buildRedirectUri[T <: Product](
    uriResponse: UriResponse[T],
    symbol: Char,
    encoding: String = "UTF-8") = {
    val params = {
      val fields = uriResponse.response.getClass.getDeclaredFields
        .map(f => URLEncoder.encode(f.getName, encoding))

      fields.zip(uriResponse.response.productIterator.toIterable).flatMap {
        case (_, None) => None
        case (f, Some(v)) => Some(f, URLEncoder.encode(v.toString, encoding))
        case (f, v) => Some(f, URLEncoder.encode(v.toString, encoding))
      }
    }.toMap
    val withState = uriResponse.state
      .map(s => params + (OAuthParams.STATE -> s))
      .getOrElse(params)

    uriResponse.baseUri + withState.map(_.productIterator.mkString("="))
      .mkString(symbol.toString, "&", "")
  }
}