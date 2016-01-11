package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, User, Client}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

/**
 * Authorization code flow granter
 * @tparam T user class
 */
class AuthorizationCodeGranter[T <: User] extends Granter[T](GrantType.AUTHORIZATION_CODE) {
  /**
   * This method processes an OAuth2 token grant request
   * @param client OAuth2 client
   * @param validationManager current validation manager
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return if request is valid: a TokenResponse instance,
   *         that represents the standard OAuth2 token grant
   *         response; otherwise, an OAuth2 error.
   */
  def process(client: Client)
             (implicit validationManager: ValidationManager[T],
              params: OAuthParams,
              ec: ExecutionContext) : Future[TokenResponse] = {
    params.getCode { code =>
      validationManager.validateCode(code, client.id, params.getRedirectUri).flatMap { res =>
        if (params.getScope.exists(x => Some(x) != res.scope))
          throw OAuthError(INVALID_SCOPE, Some(DIFFERENT_SCOPE))
        else validationManager.createAccessToken(res.client, res.user, res.scope)
      }
    }
  }
}
