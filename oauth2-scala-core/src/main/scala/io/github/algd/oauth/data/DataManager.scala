package io.github.algd.oauth.data

import io.github.algd.oauth.data.model.{AuthorizationData, User, Client}
import io.github.algd.oauth.utils.OAuthParams

import scala.concurrent.{ExecutionContext, Future}

/**
 * Trait containing all the necessary operations for
 * a OAuth2 server implementation.
 * @tparam T class that extends the User trait
 */
trait DataManager[T <: User] {

  /**
   * Obtain a OAuth2 client from an identifier
   * @param id OAuth2 client id
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return Future with optional client (found/not found)
   */
  def getClient(id: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Client]]

  /**
   * Obtain and validate an OAuth2 client from an identifier and its secret
   * @param id OAuth2 client id
   * @param secret OAuth2 client secret
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return Future with optional client (found/not found)
   */
  def getClient(id: String, secret: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Client]]

  /**
   * Validate an user from its credentials
   * @param username user login name
   * @param password user password
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return Future with optional user (found/not found)
   */
  def getUser(username: String, password: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[T]]

  /**
   * Retrieve authorization data from an authorization code.
   * This data should be queried only once, so any associated data should
   * be always removed.
   * If the authorization code is expired this method should return None.
   * @param code authorization code
   * @param params OAuth 2 parameters
   * @param ec execution context
   * @return Future with optional authorization data (found/not found)
   */
  def getAuthCodeData(code: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[AuthorizationData[T]]]

  /**
   * Get authorization data from refresh token
   * If the refresh token is expired this method should return None and
   * remove any associated data.
   * @param refreshToken refresh token
   * @param params OAuth 2 parameters
   * @param ec execution context
   * @return Future with optional authorization data (found/not found)
   */
  def getRefreshTokenData(refreshToken: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[AuthorizationData[T]]]

  /**
   * Get authorization data from access token
   * If the access token is expired this method should return None and
   * remove any associated data.
   * @param token access token
   * @param params OAuth 2 parameters
   * @param ec execution context
   * @return Future with optional authorization data (found/not found)
   */
  def getAccessTokenData(token: String)
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[Option[AuthorizationData[T]]]

  /**
   * Validate an URI using the registered client URIs
   * @param uri given URI
   * @param clientUris registered client URIs
   * @param params OAuth2 parameters
   * @return Boolean expressing the validation result
   */
  def isValidRedirectUri(uri: String, clientUris: List[String])
    (implicit params: OAuthParams): Boolean

  /**
   * Generate the string that represents the access token using the
   * authorization data
   * @param authInfo authorization data
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return generated string for access token
   */
  def generateAccessToken(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[String]

  /**
   * Generate the string that represents the refresh token using the
   * authorization data
   * @param authInfo authorization data
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return generated string for refresh token
   */
  def generateRefreshToken(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[String]

  /**
   * Generate the string that represents the authorization code using
   * the authorization data
   * @param authInfo authorization data
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return generated string for authorization code
   */
  def generateAuthCode(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[String]

  /**
   * Extract the OAuth2 scope from a instance of type T that represents
   * a user
   * @param user user
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return if the user won't be
   *         considered when scope is calculated, None should be returned.
   *         Otherwise return Some containing the set that represents the
   *         user scope
   */
  def getUserScope(user: Option[T])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Set[String]]]

  /**
   * This operation will create the instance with the authorization data using the
   * provided information
   * @param client OAuth2 client that requested the authorization
   * @param user user associated with the authorization
   * @param scope when this authorization data is associated with an
   *              authorization code, this scope represents the requested scope.
   *              Otherwise this scope will represent the assigned scope.
   * @param redirectUri request redirect_uri parameter
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return an instance with the authorization data
   */
  def buildAuthorizationData(client: Client, user: Option[T], scope: Option[Set[String]], redirectUri: Option[String] = None)
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[AuthorizationData[T]] = Future.successful {
    AuthorizationData(client, user, scope, redirectUri)
  }

  /**
   * This operation calculates the scope that will be assigned to the
   * access token.
   * The default implementation will calculate the intersection
   * between the scopes if they are defined (Some).
   * @param clientScope OAuth2 client scope
   * @param userScope user scope
   * @param requestedScope scope specified in the request
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return set that represents the scope that will be assigned to the token
   */
  def getGrantedScope(clientScope: Set[String],
    userScope: Option[Set[String]],
    requestedScope: Option[Set[String]])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Set[String]] = Future.successful{
    Seq(Some(clientScope), userScope, requestedScope).flatten.reduce(_&_)
  }

}
