package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, User, Client}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class AuthorizationCodeGranter[T <: User] extends Granter[T] {
  val name = GrantType.AUTHORIZATION_CODE

  def process(client: Client)
      (implicit validationManager: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
    params.getCode { code =>
      validationManager.validateCode(code, client.id, params.getRedirectUri).flatMap { res =>
        if (params.getScope.exists(x => Some(x) != res.scope))
          throw OAuthError(INVALID_SCOPE, ErrorDescription(21))
        else validationManager.createAccessToken(res.client, res.user, res.scope)
      }
    }
  }
}
