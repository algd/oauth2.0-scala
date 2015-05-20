package com.algd.oauth.api

import akka.http.marshalling.{ToEntityMarshaller, ToResponseMarshallable}
import akka.http.model.{StatusCode, StatusCodes}
import akka.http.server._
import com.algd.oauth.authorizer.{ResponseType, BaseAuthorizer}
import com.algd.oauth.data.model.{CodeResponse, User, TokenResponse}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.granter.BaseGranter

import scala.concurrent.ExecutionContext
import akka.http.server.Directives._
import ToResponseMarshallable._

object OAuth2Support {

  def oauthExceptionHandler(implicit ec: ExecutionContext) = ExceptionHandler {
    case e@OAuthError(error, _, _) => complete(statusCodeFor(error) -> e)
  }

  implicit class GranterRoute[T<:User](granter: BaseGranter[T]) {
    def route(params: Map[String, String])
      (implicit ec: ExecutionContext, tem: ToEntityMarshaller[TokenResponse]): Route = {
      handleExceptions(oauthExceptionHandler)(complete(granter(params)))
    }
  }

  implicit class AuthorizerRoute[T<:User, R <: Product](authorizer: BaseAuthorizer[T, R]) {
    def route(user: T, params: Map[String, String])
      (implicit ec: ExecutionContext): Route = {
      handleExceptions(oauthExceptionHandler){
        onSuccess(authorizer(user, params)) { uri =>
          val char = uri.response match { case _:CodeResponse => '#'; case _ => '?'}
          redirect(ResponseType.buildRedirectUri(uri, char), StatusCodes.MovedPermanently)
        }
      }
    }
  }

  def statusCodeFor(error: String): StatusCode = {
    import OAuthError._
    error match {
      case INVALID_CLIENT
           | INVALID_TOKEN => StatusCodes.Unauthorized
      case UNAUTHORIZED_CLIENT
           | ACCESS_DENIED
           | INSUFFICIENT_SCOPE => StatusCodes.Forbidden
      case INVALID_REQUEST
           | INVALID_GRANT
           | UNSUPPORTED_RESPONSE_TYPE
           | UNSUPPORTED_GRANT_TYPE
           | INVALID_SCOPE
           | UNSUPPORTED_TOKEN_TYPE => StatusCodes.BadRequest
      case SERVER_ERROR
           | TEMPORARILY_UNAVAILABLE => StatusCodes.InternalServerError
      case _ => StatusCodes.BadRequest
    }
  }
}
