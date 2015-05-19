package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class PasswordGranter[T <: User] extends Granter[T] {
  val name = GrantType.PASSWORD

  def process(client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
    params.getUser { (username, password) =>
      vm.validateUser(username, password).flatMap { user =>
        vm.createAccessToken(client, Some(user), params.getScope)
      }
    }
  }
}