package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{UriResponse, TokenResponse, Client, User}
import com.algd.oauth.granter.GrantType
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class ImplicitAuthorizer[T <: User] extends Authorizer[T, TokenResponse] {
  val name = GrantType.IMPLICIT

  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[UriResponse[TokenResponse]] = {
    vm.createImplicitAccessToken(client, user, params.getScope)
  }
}
