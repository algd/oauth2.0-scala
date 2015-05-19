package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class ClientCredentialsGranter[T <: User] extends Granter[T] {
  val name = GrantType.CLIENT_CREDENTIALS

  def process(client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
        vm.createAccessToken(client, None, params.getScope)
  }
}
