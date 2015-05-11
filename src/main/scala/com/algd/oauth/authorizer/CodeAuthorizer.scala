package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{CodeResponse, Client, User}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class CodeAuthorizer[T <: User] extends GenericAuthorizer[T, CodeResponse] {
  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[CodeResponse] = {
    vm.createAuthCode(client, user, params.getScope, params.getRedirectUri)
  }
}
