package com.algd.oauth.data

import com.algd.oauth.data.model._
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams
import org.joda.time.DateTime

import scala.concurrent.{ExecutionContext, Future}

class ValidationManager[T <: User](dataHandler: DataManager[T]) {

  import dataHandler._

  def validateRefreshToken(token: String, clientId: String)
      (implicit params: OAuthParams, ec: ExecutionContext) : Future[AuthorizationData[T]] = {
    for {
      tokenData <- getRefreshTokenData(token)
      nonExpiredData <- tokenData match {
        case Some(data) if data.creationDate.plusSeconds(36000).isBefore(DateTime.now) =>
          removeRefreshTokenData(token).map(_ => None)
        case other => Future.successful(other.find(_.client.id == clientId))
      }
    } yield nonExpiredData
      .getOrElse(throw OAuthError(INVALID_GRANT, ErrorDescription(9)))
  }
  
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
      .getOrElse(throw OAuthError(INVALID_TOKEN, ErrorDescription(13)))
  }

  def validateCode(code: String, clientId: String, redirectUri: Option[String])
      (implicit params: OAuthParams, ec: ExecutionContext): Future[AuthorizationData[T]] = {
    for {
      tokenData <- getAuthCodeData(code)
      nonExpiredData <- removeAuthCodeData(code) // Always remove
    } yield {
      val authData = tokenData.find(_.client.id == clientId)
        .getOrElse(throw OAuthError(INVALID_GRANT, ErrorDescription(12)))
      if (redirectUri.isDefined && redirectUri != authData.givenRedirectUri)
        throw OAuthError(UNAUTHORIZED_CLIENT, ErrorDescription(11))
      authData
    }
  }

  def createAccessToken(client: Client, user: Option[T], givenScope: Option[Set[String]],
    allowRefresh: Boolean = true, refreshing : Boolean = false)
      (implicit params: OAuthParams, ec: ExecutionContext) : Future[TokenResponse] = {
    for {
      scope <- getGrantedScope(client.scope, user.map(_.scope), givenScope)
        .map{ s => if (s.isEmpty) throw OAuthError(INVALID_SCOPE) else s }
      authInfo <- buildAuthorizationData(client, user, Some(scope)) //use final scope
      token <- generateAccessToken(authInfo)
      refreshToken <- if (allowRefresh) generateRefreshToken(authInfo).map(Some(_))
      else Future.successful(None)
    } yield TokenResponse(
      scope = scope,
      accessToken = token,
      refreshToken = refreshToken)
  }

  def createAuthCode(client: Client, user: T, givenScope: Option[Set[String]], givenUri: Option[String])
      (implicit params: OAuthParams, ec: ExecutionContext): Future[CodeResponse] = {
    for {
      scope <- getGrantedScope(client.scope, Some(user.scope), givenScope)
        .map{ s => if (s.isEmpty) throw OAuthError(INVALID_SCOPE) else s }
      authInfo <- buildAuthorizationData(client, Some(user), givenScope, givenUri) // use provided scope
      code <- generateAuthCode(authInfo)
    } yield CodeResponse(
      scope = scope,
      code = code,
      redirectUri = givenUri.getOrElse(client.redirectUris.headOption
        .getOrElse(throw OAuthError(TEMPORARILY_UNAVAILABLE, ErrorDescription(19))))
    )
  }

  def validateClient(id: String, secret: String, grantType: String)
      (implicit params: OAuthParams, ec: ExecutionContext): Future[Client] = {
    getClient(id, secret).map {
      case Some(client) if client.allowedGrants.contains(grantType) => client
      case Some(_) => throw OAuthError(UNAUTHORIZED_CLIENT, ErrorDescription(1))
      case None => throw OAuthError(INVALID_CLIENT)
    }
  }

  def validateClient(id: String, grantType: String)
      (implicit params: OAuthParams, ec: ExecutionContext): Future[Client] = {
    getClient(id).map {
      case Some(client) if client.allowedGrants.contains(grantType) => client
      case Some(_) => throw OAuthError(UNAUTHORIZED_CLIENT, ErrorDescription(1))
      case None => throw OAuthError(INVALID_CLIENT)
    }
  }

  def validateUser(username: String, password: String)
      (implicit params: OAuthParams, ec: ExecutionContext): Future[T] = {
    getUser(username, password).map{
      _.getOrElse(throw OAuthError(INVALID_GRANT))
    }
  }
}
