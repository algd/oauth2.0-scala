package io.github.algd.oauth.api

import akka.http.scaladsl.marshalling.{ToEntityMarshaller, ToResponseMarshallable}
import akka.http.scaladsl.model.{StatusCode, StatusCodes}
import akka.http.scaladsl.server._
import io.github.algd.oauth.authorizer.{ResponseType, BaseAuthorizer}
import io.github.algd.oauth.data.model.{TokenResponse, User}
import io.github.algd.oauth.exception.OAuthError
import io.github.algd.oauth.granter.BaseGranter

import scala.concurrent.ExecutionContext
import akka.http.scaladsl.server.Directives._
import ToResponseMarshallable._

/**
 * This trait enables an implicit conversion
 * from Authorizer/Granter to AuthorizerRoute/GranterRoute,
 * with a route method that returns an Akka Http Route.
 */
trait OAuth2Support {

  /**
   * Default OAuth2 exception handler.
   * @param ec execution context
   * @param tem OAuthError to entity marshaller
   * @return Request response with the proper status code.
   */
  private def oauthExceptionHandler(
    implicit ec: ExecutionContext,
    tem: ToEntityMarshaller[OAuthError]) = ExceptionHandler {
    case e@OAuthError(error, _, _) => complete(statusCodeFor(error) -> e)
  }

  /**
   * Custom OAuth2 exception handler.
   * If not defined it won't be used.
   * @return OAuth2 exception handler.
   */
  def customOAuthExceptionHandler: Option[ExceptionHandler] = None

  /**
   * Implicit class for OAuth2 Granter.
   * @param granter Oauth2 Granter
   * @tparam T user class
   */
  implicit class GranterRoute[T<:User](granter: BaseGranter[T]) {
    def route(params: Map[String, String])
      (implicit ec: ExecutionContext,
        tem: ToEntityMarshaller[TokenResponse],
        teme: ToEntityMarshaller[OAuthError]): Route = {
      handleExceptions(customOAuthExceptionHandler
        .getOrElse(oauthExceptionHandler))(complete(granter(params)))
    }
  }

  /**
   * Implicit class for OAuth2 Authorizer
   * @param authorizer OAuth2 Authorizer
   * @tparam T user class
   * @tparam R response class
   */
  implicit class AuthorizerRoute[T<:User, R <: Product](authorizer: BaseAuthorizer[T, R]) {
    def route(user: T, params: Map[String, String])
      (implicit ec: ExecutionContext, tem: ToEntityMarshaller[OAuthError]): Route = {
      handleExceptions(customOAuthExceptionHandler.getOrElse(oauthExceptionHandler)){
        onSuccess(authorizer(user, params)) { uri =>
          val char = uri.response match { case _:TokenResponse => '#'; case _ => '?'}
          redirect(ResponseType.buildRedirectUri(uri, char), StatusCodes.Found)
        }
      }
    }
  }

  /**
   * Given a OAuth2 error returns its appropiate status code.
   * @param error OAuth2 error type
   * @return Akka Http status code
   */
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

/**
 * This object enables an implicit conversion
 * from Authorizer/Granter to AuthorizerRoute/GranterRoute,
 * with a route method that returns an Akka Http Route.
 */
object OAuth2Support extends OAuth2Support
