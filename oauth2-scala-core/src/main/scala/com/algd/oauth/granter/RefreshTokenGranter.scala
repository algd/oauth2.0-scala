package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class RefreshTokenGranter[T <: User] extends Granter[T] {
  val name = GrantType.REFRESH_TOKEN

  def process(client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
    params.getRefreshToken { token =>
      vm.validateRefreshToken(token, client.id).flatMap { res =>
        vm.createAccessToken(res.client, Some(res.user), res.givenScope)
      }
    }
  }
}
