package com.algd.oauth.utils

import com.algd.oauth.authorizer.ResponseType
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._

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
      throw OAuthError(INVALID_REQUEST, ErrorDescription(12))}

  def getRefreshToken[A](f: String => A) =
    params.get(OAuthParams.REFRESH_TOKEN).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, ErrorDescription(20))}

  def getRedirectUri = params.get(OAuthParams.REDIRECT_URI)

  def getClient[A](f: (String, String) => A) =
    (params.get(OAuthParams.CLIENT_ID), params.get(OAuthParams.CLIENT_SECRET)) match {
      case (Some(id), Some(secret)) => f(id, secret)
      case _ => throw OAuthError(INVALID_CLIENT)
    }

  def getGrantType[A](f: String => A) =
    params.get(OAuthParams.GRANT_TYPE).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, ErrorDescription(5))}

  def getUser[A](f: (String, String) => A) =
    (params.get(OAuthParams.USERNAME), params.get(OAuthParams.PASSWORD)) match {
      case (Some(name), Some(pass)) => f(name, pass)
      case _ => throw OAuthError(INVALID_REQUEST)
    }

  def getScope = params.get(OAuthParams.SCOPE).map(_.split(" ").toSet)

  def getResponseType[A](f: String => A) =
    params.get(OAuthParams.RESPONSE_TYPE).map {
      ResponseType.grantTypeFor(_)
        .getOrElse(throw OAuthError(UNSUPPORTED_RESPONSE_TYPE, ErrorDescription(10)))
    }.map(f).getOrElse(throw OAuthError(INVALID_REQUEST, ErrorDescription(6)))

  def getClientId[A](f: String => A) =
    params.get(OAuthParams.CLIENT_ID).map(f).getOrElse(throw OAuthError(INVALID_CLIENT))

  def get(key: String) = params.get(key)
}