package com.algd.oauth.authorizer

import com.algd.oauth.data.{DataManager, ValidationManager}
import com.algd.oauth.data.model.{Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class BaseAuthorizer[T <: User, R](
  private val dataHandler: DataManager[T],
  private val authorizers: Map[String, Authorizer[T, R]]) {
  def apply(user: T, requestParameters: Map[String, String])
      (implicit ec: ExecutionContext): Future[R] = {
    implicit val params = new OAuthParams(requestParameters)
    implicit val vm = new ValidationManager(dataHandler)
    params.getResponseType { responseType =>
      authorizers.get(responseType).map { authorizer =>
        params.getClientId { id =>
          vm.validateClient(id, responseType).flatMap(authorizer.process(user, _))
        }
      }.getOrElse(throw OAuthError(UNSUPPORTED_RESPONSE_TYPE, ErrorDescription(4)))
    }
  }

  def +(authorizer: Authorizer[T, R]) = {
    new BaseAuthorizer(dataHandler, authorizers + (authorizer.name -> authorizer))
  }

  def ++(authorizer: Authorizer[T, R], newAuthorizers: Authorizer[T, R]*) = {
    new BaseAuthorizer(dataHandler, authorizers ++ (authorizer +: newAuthorizers).map(au => au.name -> au))
  }
}

trait Authorizer[T <: User, R] {
  val name: String

  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[R]
}