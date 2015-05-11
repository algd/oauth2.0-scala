package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class ImplicitAuthorizer[T <: User] extends Authorizer[T, TokenResponse] {
  val name = ResponseType.TOKEN

  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
    vm.createAccessToken(client, Some(user), params.getScope, allowRefresh = false)
  }
}
