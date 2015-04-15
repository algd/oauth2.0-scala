package com.algd.oauth.authorizer

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParam

import scala.concurrent.{Future, ExecutionContext}

trait GenericAuthorizer[T <: User, R] {
  def getGrantType[A](params: Map[String, String])(f: String => A) =
    params.get(OAuthParam.RESPONSE_TYPE).map {
      ResponseType.grantTypeFor(_)
        .getOrElse(throw OAuthError(UNSUPPORTED_RESPONSE_TYPE, ErrorDescription(10)))
    }.map(f).getOrElse(throw OAuthError(INVALID_REQUEST, ErrorDescription(6)))

  def getClient[A](params: Map[String, String])(f: String => A) =
    params.get(OAuthParam.CLIENT_ID).map(f).getOrElse(throw OAuthError(INVALID_CLIENT))

  def getScope(params: Map[String, String]) = params.get(OAuthParam.SCOPE).map(_.split(" ").toSet)

  def getUri(params: Map[String, String]) = params.get(OAuthParam.REDIRECT_URI)

  def apply(user: T, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext): Future[R] = {
    getGrantType(params) { grantType =>
      getClient(params) { id =>
        vm.validateClient(id, grantType).flatMap(process(user, _, params))
      }
    }
  }

  def process(user: T, client: Client, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext) : Future[R]
}
