package com.algd.oauth.data

import com.algd.oauth.data.model._
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams
import org.joda.time.DateTime

import scala.concurrent.{ExecutionContext, Future}

/**
 * Contains the validation logic using the data manager methods.
 * @param dataManager dataManager
 * @tparam T
 */
class ValidationManager[T <: User](dataManager: DataManager[T]) {
  import dataManager._

  /**
   * Get authorization data from refresh token and client id.
   * @param token refresh token
   * @param clientId client id who the token was granted to
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return Authorization data
   */
  def validateRefreshToken(token: String, clientId: String)
      (implicit params: OAuthParams, ec: ExecutionContext) : Future[AuthorizationData[T]] = {
    for {
      tokenData <- getRefreshTokenData(token)
      nonExpiredData <- tokenData match {
          //TODO: get expiration time from config
        case Some(data) if data.creationDate.plusSeconds(36000).isBefore(DateTime.now) =>
          removeRefreshTokenData(token).map(_ => None)
        case other => Future.successful(other.find(_.client.id == clientId))
      }
    } yield nonExpiredData
      .getOrElse(throw OAuthError(INVALID_GRANT, Some(INVALID_REFRESH_TOKEN)))
  }

  /**
   * Get authorization data from access token.
   * @param token access token
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return Authorization data
   */
  def validateAccessToken(token: String)
      (implicit params: OAuthParams, ec: ExecutionContext) : Future[AuthorizationData[T]] = {
    for {
      tokenData <- getAccessTokenData(token)
      nonExpiredData <- tokenData match {
        case Some(data) if data.creationDate.plusSeconds(3600).isBefore(DateTime.now) =>
          removeAccessTokenData(token).map(_ => None)
        case other => Future.successful(other)
      }
    } yield nonExpiredData
      .getOrElse(throw OAuthError(INVALID_TOKEN, Some(INVALID_OR_EXPIRED_TOKEN)))
  }

  /**
   * Get authorization data from authorization code, client id and
   * optional redirect uri
   * @param code authorization code
   * @param clientId client id who the token was granted to
   * @param redirectUri redirect uri from authorization request
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return Authorization data
   */
  def validateCode(code: String, clientId: String, redirectUri: Option[String])
      (implicit params: OAuthParams, ec: ExecutionContext): Future[AuthorizationData[T]] = {
    for {
      tokenData <- getAuthCodeData(code)
      nonExpiredData <- removeAuthCodeData(code) // Always remove
    } yield {
      val authData = tokenData.find(_.client.id == clientId)
        .getOrElse(throw OAuthError(INVALID_GRANT, Some(AUTH_CODE_NOT_FOUND)))
      if (redirectUri.isDefined && redirectUri != authData.givenRedirectUri)
        throw OAuthError(UNAUTHORIZED_CLIENT, Some(INCORRECT_REDIRECT_URI))
      authData
    }
  }

  /**
   * Creates a token associated with a client and an optional user with
   * some scope, using the data manager methods.
   * @param client OAuth2 client
   * @param user optional user
   * @param givenScope optional request scope
   * @param allowRefresh true if refresh token is granted
   * @param refreshing true if refresh token flow
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return if scope is valid, TokenResponse, that represents the standard
   *         OAuth2 token grant response.
   */
  def createAccessToken(client: Client, user: Option[T], givenScope: Option[Set[String]],
    allowRefresh: Boolean = true, refreshing : Boolean = false)
      (implicit params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
    for {
      userScope <- getUserScope(user)
      scope <- getGrantedScope(client.scope, userScope, givenScope)
        .map{ s => if (s.isEmpty) throw OAuthError(INVALID_SCOPE) else s }
      authInfo <- buildAuthorizationData(client, user, Some(scope)) //use final scope
      token <- generateAccessToken(authInfo)
      refreshToken <- if (allowRefresh) generateRefreshToken(authInfo).map(Some(_))
      else Future.successful(None)
    } yield TokenResponse(
      scope = scope.mkString(" "),
      access_token = token,
      refresh_token = refreshToken)
  }

  /**
   * Creates an access token for implicit grant flow.
   * @param client OAuth2 client
   * @param user user
   * @param givenScope request scope
   * @param params OAuth2 params
   * @param ec execution context
   * @return UriResponse, representing the response that will be
   *         converted to the parameters attached to the redirect uri.
   */
  def createImplicitAccessToken(client: Client, user: T, givenScope: Option[Set[String]])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[UriResponse[TokenResponse]] = {
    val redirectUri = params.getRedirectUri.getOrElse(client.redirectUris.headOption
      .getOrElse(throw OAuthError(TEMPORARILY_UNAVAILABLE, Some(REDIRECT_URI_REQUIRED))))
    createAccessToken(client, Some(user), givenScope, allowRefresh = false).map{
      response => UriResponse(baseUri = redirectUri, response = response)
    }
  }

  /**
   * Creates a temporal authorization code for a client and an user with a specific scope.
   * @param client OAuth2 client
   * @param user current user
   * @param givenScope requested scope
   * @param givenUri redirect uri from request
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return UriResponse, representing the response that will be
   *         converted to the parameters attached to the redirect uri.
   */
  def createAuthCode(client: Client, user: T, givenScope: Option[Set[String]], givenUri: Option[String])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[UriResponse[CodeResponse]] = {
    val redirectUri = givenUri.getOrElse(client.redirectUris.headOption
      .getOrElse(throw OAuthError(TEMPORARILY_UNAVAILABLE, Some(REDIRECT_URI_REQUIRED))))
    for {
      userScope <- getUserScope(Some(user))
      scope <- getGrantedScope(client.scope, userScope, givenScope)
        .map{ s => if (s.isEmpty) throw OAuthError(INVALID_SCOPE) else s }
      authInfo <- buildAuthorizationData(client, Some(user), givenScope, givenUri) // use provided scope
      code <- generateAuthCode(authInfo)
    } yield UriResponse(baseUri = redirectUri,
      response = CodeResponse(code))
  }

  /**
   * Retrieve client given its id, only if secret is valid
   * and client is allowed to use the specified flow.
   * For /token endpoint.
   * @param id client id
   * @param secret client secret
   * @param grantType grant type representing the flow
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return OAuth2 client
   */
  def validateClient(id: String, secret: String, grantType: String)
      (implicit params: OAuthParams, ec: ExecutionContext): Future[Client] = {
    getClient(id, secret).map {
      case Some(client) if client.allowedGrants.contains(grantType) => client
      case Some(_) => throw OAuthError(UNAUTHORIZED_CLIENT, Some(GRANT_NOT_ALLOWED))
      case None => throw OAuthError(INVALID_CLIENT)
    }
  }

  /**
   * Retrieve client given its id, only if secret is valid
   * and client is allowed to use the specified flow.
   * For /authorize endpoint.
   * @param id client id
   * @param grantType grant type representing the flow
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return OAuth2 client
   */
  def validateClient(id: String, grantType: String)
      (implicit params: OAuthParams, ec: ExecutionContext): Future[Client] = {
    getClient(id).map {
      case Some(client) if client.allowedGrants.contains(grantType) => client
      case Some(_) => throw OAuthError(UNAUTHORIZED_CLIENT, Some(GRANT_NOT_ALLOWED))
      case None => throw OAuthError(INVALID_CLIENT)
    }
  }

  /**
   * Return user given its credentials.
   * @param username user name
   * @param password user password
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return user if credentials are valid
   */
  def validateUser(username: String, password: String)
      (implicit params: OAuthParams, ec: ExecutionContext): Future[T] = {
    getUser(username, password).map{
      _.getOrElse(throw OAuthError(INVALID_GRANT))
    }
  }

  /**
   * Validate given redirect uri using the data manager method.
   * @param client OAuth2 client
   * @param uri redirect uri from request
   * @param params OAuth2 parameters
   * @param ec execution context
   * @return true if valid uri
   */
  def validateUri(client: Client, uri: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Boolean = {
    isValidRedirectUri(uri, client.redirectUris)
  }
}
