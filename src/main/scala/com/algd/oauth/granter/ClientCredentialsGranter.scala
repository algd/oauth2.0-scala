package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}

import scala.concurrent.{Future, ExecutionContext}

class ClientCredentialsGranter[T <: User] extends GenericGranter[T] {
  def process(client: Client, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext) : Future[TokenResponse] = {
        vm.createAccessToken(client, None, getScope(params))
  }
}
