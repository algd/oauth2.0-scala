package io.github.algd.oauth.utils

import io.github.algd.oauth.exception.OAuthError
import OAuthError._
import io.github.algd.oauth.authorizer.ResponseType

import scala.concurrent.{ExecutionContext, Future}

/**
 *  Contains OAuth2 parameter names
 */
object OAuthParams {
  val GRANT_TYPE = "grant_type"
  val RESPONSE_TYPE = "response_type"
  val CLIENT_ID = "client_id"
  val CLIENT_SECRET = "client_secret"
  val SCOPE = "scope"
  val STATE = "state"
  val CODE = "code"
  val REDIRECT_URI = "redirect_uri"
  val USERNAME = "username"
  val PASSWORD = "password"
  val REFRESH_TOKEN = "refresh_token"
  val ACCESS_TOKEN = "access_token"
  /// not standard
  val AUTHENTICITY_TOKEN = "authenticity_token"
}

class OAuthParams(private val params: Map[String, String] = Map.empty) {
  def getCode[A](f: String => A) =
    params.get(OAuthParams.CODE).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, Some(AUTH_CODE_NOT_FOUND))}

  def getRefreshToken[A](f: String => A) =
    params.get(OAuthParams.REFRESH_TOKEN).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, Some(MISSING_REFRESH_TOKEN))}

  def getRedirectUri = params.get(OAuthParams.REDIRECT_URI)

  def getClient[A](f: (String, String) => A) =
    (params.get(OAuthParams.CLIENT_ID), params.get(OAuthParams.CLIENT_SECRET)) match {
      case (Some(id), Some(secret)) => f(id, secret)
      case _ => throw OAuthError(INVALID_CLIENT)
    }

  def getGrantType[A](f: String => Future[A])(implicit ec: ExecutionContext) = Future {
    params.getOrElse(OAuthParams.GRANT_TYPE,
      throw OAuthError(INVALID_REQUEST, Some(MISSING_GRANT_TYPE)))}.flatMap(f)

  def getUser[A](f: (String, String) => A) =
    (params.get(OAuthParams.USERNAME), params.get(OAuthParams.PASSWORD)) match {
      case (Some(name), Some(pass)) => f(name, pass)
      case _ => throw OAuthError(INVALID_REQUEST)
    }

  def getScope = params.get(OAuthParams.SCOPE).map(_.split(" ").toSet)

  def getState = params.get(OAuthParams.STATE)

  def getResponseType[A](f: String => Future[A])(implicit ec: ExecutionContext) = Future {
    params.get(OAuthParams.RESPONSE_TYPE).map(ResponseType.grantTypeFor)
      .getOrElse(throw OAuthError(INVALID_REQUEST, Some(MISSING_RESPONSE_TYPE)))}.flatMap(f)

  def getClientId[A](f: String => A) =
    params.get(OAuthParams.CLIENT_ID).map(f).getOrElse(throw OAuthError(INVALID_CLIENT))

  def get(key: String) = params.get(key)
}