package com.algd.oauth.api

import akka.http.scaladsl.marshalling.{ToEntityMarshaller, ToResponseMarshallable}
import akka.http.scaladsl.model.{StatusCode, StatusCodes}
import akka.http.scaladsl.server._
import com.algd.oauth.authorizer.{ResponseType, BaseAuthorizer}
import com.algd.oauth.data.model.{CodeResponse, User, TokenResponse}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.granter.BaseGranter

import scala.concurrent.ExecutionContext
import akka.http.scaladsl.server.Directives._
import ToResponseMarshallable._

trait OAuth2Support {

  private def oauthExceptionHandler(
    implicit ec: ExecutionContext,
    tem: ToEntityMarshaller[OAuthError]) = ExceptionHandler {
    case e@OAuthError(error, _, _) => complete(statusCodeFor(error) -> e)
  }

  def customOAuthExceptionHandler: Option[ExceptionHandler] = None

  implicit class GranterRoute[T<:User](granter: BaseGranter[T]) {
    def route(params: Map[String, String])
      (implicit ec: ExecutionContext,
        tem: ToEntityMarshaller[TokenResponse],
        teme: ToEntityMarshaller[OAuthError]): Route = {
      handleExceptions(customOAuthExceptionHandler
        .getOrElse(oauthExceptionHandler))(complete(granter(params)))
    }
  }

  implicit class AuthorizerRoute[T<:User, R <: Product](authorizer: BaseAuthorizer[T, R]) {
    def route(user: T, params: Map[String, String])
      (implicit ec: ExecutionContext, tem: ToEntityMarshaller[OAuthError]): Route = {
      handleExceptions(customOAuthExceptionHandler.getOrElse(oauthExceptionHandler)){
        onSuccess(authorizer(user, params)) { uri =>
          val char = uri.response match { case _:TokenResponse => '#'; case _ => '?'}
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

object OAuth2Support extends OAuth2Support
