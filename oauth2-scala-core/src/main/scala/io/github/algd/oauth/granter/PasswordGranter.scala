package io.github.algd.oauth.granter

import io.github.algd.oauth.data.ValidationManager
import io.github.algd.oauth.data.model.{TokenResponse, Client, User}
import io.github.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

/**
 * Resource owner password credentials flow granter
 * @tparam T user class
 */
class PasswordGranter[T <: User] extends Granter[T](GrantType.PASSWORD) {
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
    params.getUser { (username, password) =>
      vm.validateUser(username, password).flatMap { user =>
        vm.createAccessToken(client, Some(user), params.getScope)
      }
    }
  }
}