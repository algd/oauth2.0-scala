package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, User, Client}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._

import scala.concurrent.{Future, ExecutionContext}

class AuthorizationCodeGranter[T <: User] extends GenericGranter[T] {
  def process(client: Client, params: Map[String, String])
      (implicit validationManager: ValidationManager[T], ec: ExecutionContext) : Future[TokenResponse] = {
    getCode(params) { code =>
      validationManager.validateCode(code, client.id, getRedirectUri(params)).flatMap { res =>
        if (getScope(params).exists(x => Some(x) != res.givenScope))
          throw OAuthError(INVALID_SCOPE, ErrorDescription(21))
        else validationManager.createAccessToken(res.client, Some(res.user), res.givenScope)
      }
    }
  }
}
