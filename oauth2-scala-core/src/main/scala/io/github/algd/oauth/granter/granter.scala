package io.github.algd.oauth.granter

import io.github.algd.oauth.exception.OAuthError
import OAuthError._
import io.github.algd.oauth.data.{ValidationManager, DataManager}
import io.github.algd.oauth.data.model.{Client, TokenResponse, User}
import io.github.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

/**
 * This object will redirect the request to the proper token
 * granter based on the grant_type parameter.
 * @param dataManager used dataManager
 * @param granters map that associates the grant_type field value
 *                 with the granter
 * @tparam T user class
 */
class BaseGranter[T <: User](private val dataManager: DataManager[T],
  private val granters: Map[String, Granter[T]] = Map.empty[String, Granter[T]]) {

  /**
   * Process a request using request parameters.
   * @param requestParameters OAuth2 request parameters
   * @param ec execution context
   * @return if request is valid: a TokenResponse instance,
   *         that represents the standard OAuth2 token grant
   *         response; otherwise, an OAuth2 error.
   */
  def apply(requestParameters: Map[String, String])
      (implicit ec: ExecutionContext): Future[TokenResponse] = {
    implicit val params = new OAuthParams(requestParameters)
    implicit val vm = new ValidationManager(dataManager)
    params.getGrantType { grantType =>
      granters.get(grantType).map { granter =>
        params.getClient { (id, secret) =>
          vm.validateClient(id, secret, grantType).flatMap(granter.process)
            .map(_.copy(state = params.getState))
        }
      }.getOrElse(throw OAuthError(UNSUPPORTED_GRANT_TYPE, Some(UNSUPPORTED_GRANT)))
    }.recover{
      case o: OAuthError => throw o.copy(state = params.getState)
      case e: Throwable => throw e
    }
  }

  /**
   * Add a granter.
   * @param granter granter
   * @return the same base with a new granter
   */
  def +(granter: Granter[T]) = {
    new BaseGranter(dataManager, granters + (granter.name -> granter))
  }

  /**
   * Add a sequence of granters
   * @param granter first granter
   * @param newGranters sequence of granters
   * @return the same base with new granters
   */
  def ++(granter: Granter[T], newGranters: Granter[T]*) = {
    new BaseGranter(dataManager, granters ++ (granter +: newGranters).map(g => g.name -> g))
  }

}

/**
 * Granters should extend and implement this trait
 * @param name granter name
 * @tparam T user class
 */
abstract class Granter[T <: User](val name: String) {
  /**
   * This method processes an OAuth2 token grant request
   * @param client OAuth2 client
   * @param vm current validation manager
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return if request is valid: a TokenResponse instance,
   *         that represents the standard OAuth2 token grant
   *         response; otherwise, an OAuth2 error.
   */
  def process(client: Client)
      (implicit vm: ValidationManager[T], params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse]
}
