package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{CodeResponse, Client, User}

import scala.concurrent.{Future, ExecutionContext}

class CodeAuthorizer[T <: User] extends GenericAuthorizer[T, CodeResponse] {
  def process(user: T, client: Client, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext) : Future[CodeResponse] = {
    vm.createAuthCode(client, user, getScope(params), getUri(params))
  }
}
