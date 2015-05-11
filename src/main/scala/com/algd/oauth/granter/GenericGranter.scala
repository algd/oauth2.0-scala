package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

trait GenericGranter[T <: User] {

  def apply(requestParameters: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext): Future[TokenResponse] = {
    implicit val params = new OAuthParams(requestParameters)
    params.getGrantType { grantType =>
      params.getClient { (id, secret) =>
        vm.validateClient(id, secret, grantType).flatMap(process)
      }
    }
  }

  def process(client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse]
}
