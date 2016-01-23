package io.github.algd.oauth.authorizer

import java.net.URLEncoder
import io.github.algd.oauth.data.model.UriResponse
import io.github.algd.oauth.granter.GrantType
import io.github.algd.oauth.utils.OAuthParams

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

  /**
   * This method builds the url that the user will be redirected to.
   * @param uriResponse
   * @param symbol
   * @param encoding
   * @tparam T
   * @return
   */
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