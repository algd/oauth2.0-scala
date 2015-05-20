package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{UriResponse, CodeResponse, Client, User}
import com.algd.oauth.granter.GrantType
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class CodeAuthorizer[T <: User] extends Authorizer[T, CodeResponse] {
  val name = GrantType.AUTHORIZATION_CODE

  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[UriResponse[CodeResponse]] = {
    vm.createAuthCode(client, user, params.getScope, params.getRedirectUri)
  }
}
