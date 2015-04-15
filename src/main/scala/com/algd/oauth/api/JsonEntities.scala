package com.algd.oauth.api

import com.algd.oauth.data.model.TokenResponse
import spray.json.DefaultJsonProtocol

object JsonEntities extends DefaultJsonProtocol {
  case class JsonTokenResponse(
    access_token: String,
    token_type: String,
    scope: String,
    expires_in: Option[Long] = None,
    refresh_token: Option[String] = None,
    state: Option[String] = None)

  def jsonWithState(token: TokenResponse, state: Option[String] = None) = {
    JsonTokenResponse(
      access_token = token.accessToken,
      token_type = "Bearer",
      scope = token.scope.mkString(" "),
      expires_in = Some(3600),
      refresh_token = token.refreshToken,
      state = state)
  }

  implicit val TokenResponseFormat = jsonFormat6(JsonTokenResponse)
}
