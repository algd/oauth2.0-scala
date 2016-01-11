package io.github.algd.oauth.granter

import io.github.algd.oauth.data.ValidationManager
import io.github.algd.oauth.data.model.{TokenResponse, User, Client}
import io.github.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

/**
 * Refresh token flow granter
 * @tparam T user class
 */
class RefreshTokenGranter[T <: User] extends Granter[T](GrantType.REFRESH_TOKEN) {
  /**
   * This method processes an OAuth2 token grant request
   * @param client OAuth2 client
   * @param vm current validation manager
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return if request is valid: a TokenResponse instance,
   *         that represents the standard OAuth2 token grant
   *         response; otherwise, an OAuth2 error.
   */
  def process(client: Client)
             (implicit vm: ValidationManager[T],
              params: OAuthParams,
              ec: ExecutionContext) : Future[TokenResponse] = {
    params.getRefreshToken { token =>
      vm.validateRefreshToken(token, client.id).flatMap { res =>
        vm.createAccessToken(res.client, res.user, res.scope)
      }
    }
  }
}
