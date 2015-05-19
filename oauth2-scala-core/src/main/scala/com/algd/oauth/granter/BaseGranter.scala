package com.algd.oauth.granter

import com.algd.oauth.data.{DataManager, ValidationManager}
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class BaseGranter[T <: User](private val dataHandler: DataManager[T],
  private val granters: Map[String, Granter[T]] = Map.empty[String, Granter[T]]) {

  def apply(requestParameters: Map[String, String])
      (implicit ec: ExecutionContext): Future[TokenResponse] = {
    implicit val params = new OAuthParams(requestParameters)
    implicit val vm = new ValidationManager(dataHandler)
    params.getGrantType { grantType =>
      granters.get(grantType).map { granter =>
        params.getClient { (id, secret) =>
          vm.validateClient(id, secret, grantType).flatMap(granter.process)
            .map(_.copy(state = params.getState))
        }
      }.getOrElse(throw OAuthError(UNSUPPORTED_GRANT_TYPE, ErrorDescription(3)))
    }.recover{
      case o: OAuthError => throw o.copy(state = params.getState)
      case e: Throwable => throw e
    }
  }

  def +(granter: Granter[T]) = {
    new BaseGranter(dataHandler, granters + (granter.name -> granter))
  }

  def ++(granter: Granter[T], newGranters: Granter[T]*) = {
    new BaseGranter(dataHandler, granters ++ (granter +: newGranters).map(g => g.name -> g))
  }

}

trait Granter[T <: User] {
  val name: String

  def process(client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse]
}
