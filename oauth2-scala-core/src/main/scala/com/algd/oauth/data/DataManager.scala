package com.algd.oauth.data

import com.algd.oauth.data.model.{User, AuthorizationData, Client}
import com.algd.oauth.utils.OAuthParams

import scala.concurrent.Future

trait DataManager[T <: User] {

  def getClient(id: String)
    (implicit params: OAuthParams): Future[Option[Client]]

  def getClient(id: String, secret: String)
    (implicit params: OAuthParams): Future[Option[Client]]

  def getUser(username: String, password: String)
    (implicit params: OAuthParams): Future[Option[T]]

  def getAuthCodeData(code: String)
    (implicit params: OAuthParams): Future[Option[AuthorizationData[T]]]

  def removeAuthCodeData(code: String)
    (implicit params: OAuthParams): Future[Option[String]]

  def getRefreshTokenData(refreshToken: String)
    (implicit params: OAuthParams): Future[Option[AuthorizationData[T]]]

  def removeRefreshTokenData(refreshToken: String)
    (implicit params: OAuthParams): Future[Option[String]]

  def getAccessTokenData(token: String)
    (implicit params: OAuthParams) : Future[Option[AuthorizationData[T]]]

  def removeAccessTokenData(token: String)
    (implicit params: OAuthParams): Future[Option[String]]

  def isValidRedirectUri(uri: String, clientUris: List[String])
    (implicit params: OAuthParams): Boolean

  def generateAccessToken(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams) : Future[String]

  def generateRefreshToken(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams) : Future[String]

  def generateAuthCode(authInfo: AuthorizationData[T])
    (implicit params: OAuthParams) : Future[String]

  def buildAuthorizationData(client: Client, user: Option[T], scope: Option[Set[String]], redirectUri: Option[String] = None)
    (implicit params: OAuthParams) : Future[AuthorizationData[T]] = Future.successful {
    AuthorizationData(client, user, scope, redirectUri)
  }

  def getGrantedScope(clientScope: Set[String],
    userScope: Option[Set[String]],
    requestedScope: Option[Set[String]])(
    implicit params: OAuthParams): Future[Set[String]] = Future.successful{
    Seq(Some(clientScope), userScope, requestedScope).flatten.reduce(_&_)
  }

}
