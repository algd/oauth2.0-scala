package com.algd.oauth.api

import java.net.URLEncoder

import com.algd.oauth.data.model.TokenResponse
import com.algd.oauth.exception.OAuthError
import spray.json.DefaultJsonProtocol

object JsonEntities extends DefaultJsonProtocol {
  /*trait ParameterResponse { _: Product =>
    def toMap: Map[String, String] = {
      val fields = getClass.getDeclaredFields
      fields.zip(productIterator.toIterable).flatMap {
        case (_, None) => None
        case (f, Some(v)) => Some(f.getName, v.toString)
        case (f, v) => Some(f.getName, v.toString)
      }.toMap
    }
  }



  implicit class UriParameter(p: Product) {
    def toQueryString(symbol: String, encoding: String = "UTF-8") = {
      val fields = p.getClass.getDeclaredFields
        .map(f => URLEncoder.encode(f.getName, encoding))

      fields.zip(p.productIterator.toIterable).flatMap {
        case (_, None) => None
        case (f, Some(v)) => Some(f, URLEncoder.encode(v.toString, encoding))
        case (f, v) => Some(f, URLEncoder.encode(v.toString, encoding))
      }
    }.map(_.productIterator.mkString("=")).mkString(symbol, "&", "")
  }*/

  case class JsonTokenResponse(
    access_token: String,
    token_type: String,
    scope: String,
    expires_in: Option[Long] = None,
    refresh_token: Option[String] = None,
    state: Option[String] = None)

  case class JsonErrorResponse(
    error: String,
    state: Option[String] = None,
    error_description: Option[String] = None,
    error_uri: Option[String] = None)

  def jsonTokenWithState(token: TokenResponse, state: Option[String] = None) = {
    JsonTokenResponse(
      access_token = token.accessToken,
      token_type = "Bearer",
      scope = token.scope.mkString(" "),
      expires_in = Some(3600),
      refresh_token = token.refreshToken,
      state = state)
  }

  def jsonErrorWithState(error: OAuthError, state: Option[String]) = {
    JsonErrorResponse(error.error, state, error.description)
  }

  implicit val TokenResponseFormat = jsonFormat6(JsonTokenResponse)
}