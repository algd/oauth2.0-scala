package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}

import scala.concurrent.{Future, ExecutionContext}

class ImplicitAuthorizer[T <: User] extends GenericAuthorizer[T, TokenResponse] {
  def process(user: T, client: Client, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext) : Future[TokenResponse] = {
    vm.createAccessToken(client, Some(user), getScope(params), allowRefresh = false)
  }
}
