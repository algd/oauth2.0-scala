package com.algd.oauth.authorizer

import com.algd.oauth.data.{DataManager, ValidationManager}
import com.algd.oauth.data.model.{UriResponse, Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class BaseAuthorizer[T <: User, R <: Product](
  private val dataHandler: DataManager[T],
  private val authorizers: Map[String, Authorizer[T, R]] = Map.empty[String, Authorizer[T, R]]) {
  def apply(user: T, requestParameters: Map[String, String])
      (implicit ec: ExecutionContext): Future[UriResponse[R]] = {
    implicit val params = new OAuthParams(requestParameters)
    implicit val vm = new ValidationManager(dataHandler)
    params.getResponseType { responseType =>
      authorizers.get(responseType).map { authorizer =>
        params.getClientId { id =>
          vm.validateClient(id, responseType).map { client =>
            if (params.getRedirectUri.exists(!vm.validateUri(client, _)))
              throw new OAuthError(UNAUTHORIZED_CLIENT, ErrorDescription(11))
            else client
          }.flatMap(authorizer.process(user, _)).map(_.copy(state = params.getState))
        }
      }.getOrElse(throw OAuthError(UNSUPPORTED_RESPONSE_TYPE, ErrorDescription(4)))
    }.recover{
      case o: OAuthError => throw o.copy(state = params.getState)
      case e: Throwable => throw e
    }
  }

  def +[R1 >: R <: Product](authorizer: Authorizer[T, R1]): BaseAuthorizer[T, R1] = {
    new BaseAuthorizer[T, R1](dataHandler, authorizers + (authorizer.name -> authorizer))
  }

  def ++[R1 >: R <: Product](authorizer: Authorizer[T, R1], newAuthorizers: Authorizer[T, R1]*): BaseAuthorizer[T, R1] = {
    new BaseAuthorizer(dataHandler, authorizers ++ (authorizer +: newAuthorizers).map(au => au.name -> au))
  }
}

trait Authorizer[T <: User, +R <: Product] {
  val name: String

  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[UriResponse[R]]

}