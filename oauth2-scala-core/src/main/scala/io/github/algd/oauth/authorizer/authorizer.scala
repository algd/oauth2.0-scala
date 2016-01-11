package io.github.algd.oauth.authorizer

import io.github.algd.oauth.exception.OAuthError
import OAuthError._
import io.github.algd.oauth.data.{ValidationManager, DataManager}
import io.github.algd.oauth.data.model.{UriResponse, Client, User}
import io.github.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

/**
 * This object will redirect the request to the proper authorizer
 * based on the response_type parameter.
 * @param dataManager used dataManager
 * @param authorizers map that associates the response_type field value
 *                    with the authorizer
 * @tparam T user class
 * @tparam R class for uri response
 */
class BaseAuthorizer[T <: User, R <: Product](
  private val dataManager: DataManager[T],
  private val authorizers: Map[String, Authorizer[T, R]] = Map.empty[String, Authorizer[T, R]]) {
  /**
   * Process a request using user data.
   * @param user current user
   * @param requestParameters parameters extracted from the request
   * @param ec execution context
   * @return a response that will be converted to a sequence of parameters
   *         to be attached to a redirection uri.
   */
  def apply(user: T, requestParameters: Map[String, String])
      (implicit ec: ExecutionContext): Future[UriResponse[R]] = {
    implicit val params = new OAuthParams(requestParameters)
    implicit val vm = new ValidationManager(dataManager)
    params.getResponseType { responseType =>
      authorizers.get(responseType).map { authorizer =>
        params.getClientId { id =>
          vm.validateClient(id, responseType).map { client =>
            if (params.getRedirectUri.exists(!vm.validateUri(client, _)))
              throw new OAuthError(UNAUTHORIZED_CLIENT, Some(INCORRECT_REDIRECT_URI))
            else client
          }.flatMap(authorizer.process(user, _)).map(_.copy(state = params.getState))
        }
      }.getOrElse(throw OAuthError(UNSUPPORTED_RESPONSE_TYPE, Some(UNSUPPORTED_REQUEST)))
    }.recover{
      case o: OAuthError => throw o.copy(state = params.getState)
      case e: Throwable => throw e
    }
  }

  /**
   * Add an authorizer.
   * @param authorizer authorizer
   * @tparam R1 response class
   * @return the same base with a new authorizer
   */
  def +[R1 >: R <: Product](authorizer: Authorizer[T, R1]): BaseAuthorizer[T, R1] = {
    new BaseAuthorizer[T, R1](dataManager, authorizers + (authorizer.name -> authorizer))
  }

  /**
   * Add a sequence of authorizers.
   * @param authorizer authorizer
   * @param newAuthorizers sequence of authorizers
   * @tparam R1 response class
   * @return the same base with more authorizers
   */
  def ++[R1 >: R <: Product](authorizer: Authorizer[T, R1], newAuthorizers: Authorizer[T, R1]*): BaseAuthorizer[T, R1] = {
    new BaseAuthorizer(dataManager, authorizers ++ (authorizer +: newAuthorizers).map(au => au.name -> au))
  }
}

/**
 * Authorizers should extend and implement this trait
 * @param name authorizer name
 * @tparam T user class
 * @tparam R response class
 */
abstract class Authorizer[T <: User, +R <: Product](val name: String) {
  /**
   * This method processes an OAuth2 authorization request
   * @param user current user
   * @param client OAuth2 client
   * @param vm current validation manager
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return a response that will be converted to a sequence of parameters
   *         to be attached to a redirection uri.
   */
  def process(user: T, client: Client)
      (implicit vm: ValidationManager[T],
       params: OAuthParams,
       ec: ExecutionContext) : Future[UriResponse[R]]

}