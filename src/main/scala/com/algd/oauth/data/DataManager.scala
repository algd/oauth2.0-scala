package com.algd.oauth.data

import akka.http.util.DateTime
import com.algd.oauth.data.model._
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._

import scala.concurrent.Future

trait ValidationManager[T <:  User] {
  import scala.concurrent.ExecutionContext.Implicits.global
  val clients: scala.collection.mutable.Map[String, (String, Client)] = scala.collection.mutable.Map(
    "client" -> ("client_secret", Client("Test Client", "client", Set("test"), Set("authorization_code"), List()))
  )
  val users: scala.collection.mutable.Map[String, (String, T)] = scala.collection.mutable.Map()
  val authCodes: scala.collection.mutable.Map[String, AuthorizationData[T]] = scala.collection.mutable.Map()
  val tokenDatas: scala.collection.mutable.Map[String, AuthorizationData[T]] = scala.collection.mutable.Map()
  val refTokenDatas: scala.collection.mutable.Map[String, AuthorizationData[T]] = scala.collection.mutable.Map()

  ///////////////////////////////////////////////

  def getClient(id: String): Future[Option[Client]] = {
    Future.successful(clients.get(id).map(_._2))
  }

  def getClient(id: String, secret: String): Future[Option[Client]] = {
    Future.successful(clients.get(id).find(_._1 == secret).map(_._2))
  }

  def getUser(username: String, password: String): Future[Option[T]] = {
    Future.successful(users.get(username).find(_._1 == password).map(_._2))
  }

  def getAuthCodeData(code: String): Future[Option[AuthorizationData[T]]] = {
    Future.successful(authCodes.get(code))
  }

  def removeAuthCodeData(code: String): Future[Option[String]] = {
    Future.successful(authCodes.remove(code).map(_ => code))
  }

  def getRefreshTokenData(refreshToken: String): Future[Option[AuthorizationData[T]]] = {
    Future.successful(refTokenDatas.get(refreshToken))
  }

  def removeRefreshTokenData(refreshToken: String): Future[Option[String]] = {
    Future.successful(refTokenDatas.remove(refreshToken).map(_ => refreshToken))
  }

  def getAccessTokenData(token: String) : Future[Option[AuthorizationData[T]]] = {
    Future.successful(tokenDatas.get(token))
  }

  def removeAccessTokenData(token: String): Future[Option[String]] = {
    Future.successful(tokenDatas.remove(token).map(_ => token))
  }

  def isValidRedirectUri(uri: String, clientUris: List[String]): Boolean = {
    clientUris.exists(clientUri => uri.startsWith(clientUri))
  }

  def generateAccessToken(client: Client, user: Option[T], scope: Set[String]) : Future[String] = {
    val token = java.util.UUID.randomUUID().toString
    //tokenDatas += token -> AuthorizationData[T](client, user.orNull[T], Some(scope))
    Future.successful(token)
  }

  def generateRefreshToken(client: Client, user: Option[T], scope: Set[String]) : Future[String] = {
    val token = java.util.UUID.randomUUID().toString
    //refTokenDatas += token -> AuthorizationData[T](client, user.get, Some(scope))
    Future.successful(token)
  }

  def generateAuthCode(client: Client, user: T, scope: Option[Set[String]], redirectUri: Option[String]) : Future[String] = {
    val code = java.util.UUID.randomUUID.toString.substring(0, 4).toUpperCase
    authCodes += code -> AuthorizationData[T](client, user, scope, redirectUri)
    Future.successful(code)
  }

  // TODO: MyImpl
  // TODO: MyImpl
  // TODO: MyImpl


  def validateRefreshToken(token: String, clientId: String) : Future[AuthorizationData[T]] = {
    for {
      tokenData <- getRefreshTokenData(token)
      nonExpiredData <- tokenData match {
        case Some(data) if data.creationDate + 36000000 < DateTime.now =>
          removeRefreshTokenData(token).map(_ => None)
        case other => Future.successful(other.find(_.client.id == clientId))
      }
    } yield nonExpiredData
      .getOrElse(throw OAuthError(INVALID_GRANT, ErrorDescription(9)))
  }
  
  def validateAccessToken(token: String) : Future[AuthorizationData[T]] = {
    for {
      tokenData <- getAccessTokenData(token)
      nonExpiredData <- tokenData match {
        case Some(data) if data.creationDate + 3600000 < DateTime.now =>
          removeAccessTokenData(token).map(_ => None)
        case other => Future.successful(other)
      }
    } yield nonExpiredData
      .getOrElse(throw OAuthError(INVALID_TOKEN, ErrorDescription(13)))
  }

  def validateCode(code: String, clientId: String, redirectUri: Option[String]): Future[AuthorizationData[T]] = {
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

  /*def validateRefreshToken(refreshToken: String, clientId: String): Future[AuthorizationData[T]] = {
    getRefreshTokenData(refreshToken).map { optData =>
      optData.find(data => data.client.id == clientId && !data.isExpired)
        .getOrElse(throw new Exception("INVALID_GRANT invalid refresh_token"))
    }
  }*/


  def createAccessToken(client: Client, user: Option[T], givenScope: Option[Set[String]],
    allowRefresh: Boolean = true, refreshing : Boolean = false) : Future[TokenResponse] = {

    val userClientScope = user.map(_.scope & client.scope).getOrElse(client.scope)
    val scope = givenScope.map(_ & userClientScope).getOrElse(userClientScope)
    if (scope.isEmpty)
      Future.failed(OAuthError(INVALID_SCOPE, Some("allowed scopes: " + userClientScope)))
    else for {
      token <- generateAccessToken(client, user, scope)
      refreshToken <- if (allowRefresh) generateRefreshToken(client, user, scope).map(Some(_))
      else Future.successful(None)
    } yield TokenResponse(
        scope = scope,
        accessToken = token,
        refreshToken = refreshToken)
  }

  def createAuthCode(client: Client, user: T, givenScope: Option[Set[String]], givenUri: Option[String]): Future[CodeResponse] = {
    val userClientScope = user.scope & client.scope
    val scope = givenScope.map(_ & userClientScope).getOrElse(userClientScope)
    if (scope.isEmpty)
      Future.failed(OAuthError(INVALID_SCOPE, Some("allowed scopes: " + userClientScope)))
    else for {
      code <- generateAuthCode(client, user, givenScope, givenUri)
    } yield CodeResponse(
        scope = scope,
        code = code,
        redirectUri = givenUri.getOrElse(client.redirectUris.headOption
          .getOrElse(throw OAuthError(TEMPORARILY_UNAVAILABLE, ErrorDescription(19))))
      )
  }

  def validateClient(id: String, secret: String, grantType: String): Future[Client] = {
    getClient(id, secret).map {
      case Some(client) if client.allowedGrants.contains(grantType) => client
      case Some(_) => throw OAuthError(UNAUTHORIZED_CLIENT, ErrorDescription(1))
      case None => throw OAuthError(INVALID_CLIENT)
    }
  }

  def validateClient(id: String, grantType: String): Future[Client] = {
    getClient(id).map {
      case Some(client) if client.allowedGrants.contains(grantType) => client
      case Some(_) => throw OAuthError(UNAUTHORIZED_CLIENT, ErrorDescription(1))
      case None => throw OAuthError(INVALID_CLIENT)
    }
  }

  def validateUser(username: String, password: String): Future[T] = {
    getUser(username, password).map{
      _.getOrElse(throw OAuthError(INVALID_GRANT))
    }
  }
}
