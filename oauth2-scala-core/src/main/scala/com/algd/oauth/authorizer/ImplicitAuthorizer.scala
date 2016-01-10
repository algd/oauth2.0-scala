package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{UriResponse, TokenResponse, Client, User}
import com.algd.oauth.granter.GrantType
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

/**
 * Authorizer for OAuth2 implicit grant authorization flow
 * @tparam T user class
 */
class ImplicitAuthorizer[T <: User] extends Authorizer[T, TokenResponse](GrantType.IMPLICIT) {
  /**
   * This method processes an OAuth2 authorization request
   * @param user current user
   * @param client OAuth2 client
   * @param vm current validation manager
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return a response that will be converted to a sequence of parameters
   *         to be attached to a redirection uri.
   */
  def process(user: T, client: Client)
             (implicit vm: ValidationManager[T],
              params: OAuthParams,
              ec: ExecutionContext) : Future[UriResponse[TokenResponse]] = {
    vm.createImplicitAccessToken(client, user, params.getScope)
  }
}
