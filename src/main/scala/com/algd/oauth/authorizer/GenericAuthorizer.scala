package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

trait GenericAuthorizer[T <: User, R] {
  def apply(user: T, requestParameters: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext): Future[R] = {
    implicit val params = new OAuthParams(requestParameters)
    params.getResponseType { grantType =>
      params.getClientId { id =>
        vm.validateClient(id, grantType).flatMap(process(user, _))
      }
    }
  }

  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[R]
}
