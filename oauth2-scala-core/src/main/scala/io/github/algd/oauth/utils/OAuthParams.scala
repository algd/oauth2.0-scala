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

/**
 * Wrapper for OAuth2 parameters with some utils
 * @param params OAuth parameters extracted from request
 */
class OAuthParams(private val params: Map[String, String] = Map.empty) {
  /**
   * If authorization code is present, it calls f function with it.
   * Otherwise it throws an OAuth2 exception.
   * @param f function that expects the authorization code
   * @tparam A returning type
   * @return result using the authorization code
   */
  def getCode[A](f: String => A) =
    params.get(OAuthParams.CODE).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, Some(AUTH_CODE_NOT_FOUND))}

  /**
   * If refresh token is present, it calls f function with it.
   * Otherwise it throws an OAuth2 exception.
   * @param f function that expects the refresh token
   * @tparam A returning type
   * @return result using the refresh token
   */
  def getRefreshToken[A](f: String => A) =
    params.get(OAuthParams.REFRESH_TOKEN).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, Some(MISSING_REFRESH_TOKEN))}

  /**
   * Extract the redirect uri parameter as an optional string
   * @return optional redirect uri
   */
  def getRedirectUri: Option[String] = params.get(OAuthParams.REDIRECT_URI)

  /**
   * If client credentials are present, it calls f function with them.
   * Otherwise it throws an OAuth2 exception.
   * @param f function that expects the client credentials
   * @tparam A returning type
   * @return result using the client credentials
   */
  def getClient[A](f: (String, String) => A) =
    (params.get(OAuthParams.CLIENT_ID), params.get(OAuthParams.CLIENT_SECRET)) match {
      case (Some(id), Some(secret)) => f(id, secret)
      case _ => throw OAuthError(INVALID_CLIENT)
    }

  /**
   * If grant type parameter is present, it calls f function with the value.
   * Otherwise it throws an OAuth2 exception.
   * @param f function that expects a grant type
   * @param ec execution context
   * @tparam A returning type
   * @return result using the grant type
   */
  def getGrantType[A](f: String => Future[A])
                     (implicit ec: ExecutionContext): Future[A] = Future {
    params.getOrElse(OAuthParams.GRANT_TYPE,
      throw OAuthError(INVALID_REQUEST, Some(MISSING_GRANT_TYPE)))}.flatMap(f)

  /**
   * If user credentials are present, it calls f function with them.
   * Otherwise it throws an OAuth2 exception.
   * @param f function that expects the user credentials
   * @tparam A returning type
   * @return result using the user credentials
   */
  def getUser[A](f: (String, String) => A): A =
    (params.get(OAuthParams.USERNAME), params.get(OAuthParams.PASSWORD)) match {
      case (Some(name), Some(pass)) => f(name, pass)
      case _ => throw OAuthError(INVALID_REQUEST)
    }

  /**
   * Get scope parameter
   * @return if scope parameter is present, it returns a set with the permissions,
   *         otherwise it returns None
   */
  def getScope: Option[Set[String]] = params.get(OAuthParams.SCOPE).map(_.split(" ").toSet)

  /**
   * Get state parameter
   * @return it returns an optional string with the state
   */
  def getState: Option[String] = params.get(OAuthParams.STATE)

  /**
   * If response type parameter is present, it calls f function with the value.
   * Otherwise it throws an OAuth2 exception.
   * @param f function that expects a response type
   * @param ec execution context
   * @tparam A returning type
   * @return result using the response type
   */
  def getResponseType[A](f: String => Future[A])(implicit ec: ExecutionContext) = Future {
    params.get(OAuthParams.RESPONSE_TYPE).map(ResponseType.grantTypeFor)
      .getOrElse(throw OAuthError(INVALID_REQUEST, Some(MISSING_RESPONSE_TYPE)))}.flatMap(f)

  /**
   * If client id parameter is present, it calls f function with the value.
   * Otherwise it throws and OAuth2 exception.
   * @param f function that expects the OAuth2 client
   * @tparam A returning type
   * @return result using the client id
   */
  def getClientId[A](f: String => A) =
    params.get(OAuthParams.CLIENT_ID).map(f).getOrElse(throw OAuthError(INVALID_CLIENT))

  /**
   * Get a specific parameter
   * @param key parameter
   * @return optional value
   */
  def get(key: String) = params.get(key)
}