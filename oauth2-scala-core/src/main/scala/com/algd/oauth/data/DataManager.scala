package com.algd.oauth.data

import com.algd.oauth.data.model.{User, AuthorizationData, Client}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.{ExecutionContext, Future}

trait DataManager[T <: User] {

  def getClient(id: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Client]]

  def getClient(id: String, secret: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Client]]

  def getUser(username: String, password: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[T]]

  def getAuthCodeData(code: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[AuthorizationData[T]]]

  def removeAuthCodeData(code: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[String]]

  def getRefreshTokenData(refreshToken: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[AuthorizationData[T]]]

  def removeRefreshTokenData(refreshToken: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[String]]

  def getAccessTokenData(token: String)
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[Option[AuthorizationData[T]]]

  def removeAccessTokenData(token: String)
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[String]]

  def isValidRedirectUri(uri: String, clientUris: List[String])
    (implicit params: OAuthParams): Boolean

  def generateAccessToken(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[String]

  def generateRefreshToken(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[String]

  def generateAuthCode(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[String]

  def getUserScope(user: Option[T])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Set[String]]]

  def buildAuthorizationData(client: Client, user: Option[T], scope: Option[Set[String]], redirectUri: Option[String] = None)
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[AuthorizationData[T]] = Future.successful {
    AuthorizationData(client, user, scope, redirectUri)
  }

  def getGrantedScope(clientScope: Set[String],
    userScope: Option[Set[String]],
    requestedScope: Option[Set[String]])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Set[String]] = Future.successful{
    Seq(Some(clientScope), userScope, requestedScope).flatten.reduce(_&_)
  }

}
