package com.algd.oauth.data.model

import org.joda.time.DateTime

/**
 * OAuth2 Client
 * @param name client name
 * @param id client id
 * @param scope set that represents the client scope
 * @param allowedGrants set that represents the request types
 *                      that the client is allowed to perform
 * @param redirectUris possible redirect uris that belongs to
 *                     this client
 */
case class Client(
  name: String,
  id: String,
  scope: Set[String],
  allowedGrants: Set[String],
  redirectUris: List[String])

/**
 * The custom user class should extend this trait
 */
trait User {
  val id: String
}

/**
 * This object represents the response when
 * an access token is issued
 * @param scope granted scope
 * @param access_token code that represents the access token
 * @param refresh_token code that represents the refresh token (optional)
 * @param state if provided in the request, it will be the same value
 */
case class TokenResponse(
  scope: String,
  access_token: String,
  refresh_token: Option[String] = None,
  state: Option[String] = None)

/**
 * This class represents the response when an authorization code
 * is issued
 * @param code authorization code
 */
case class CodeResponse(code: String)

/**
 * This will be used in order to transform a response to
 * a sequence of parameters attached to the redirection uri
 * @param baseUri
 * @param response
 * @param state
 * @tparam R
 */
case class UriResponse[+R <: Product](
  baseUri: String,
  response: R,
  state: Option[String] = None)

/**
 * This class will store the data of an access token,
 * a refresh token or an authorization code
 * @param client OAuth2 client
 * @param user user (if any)
 * @param scope requested or assigned scope
 * @param givenRedirectUri request redirect uri
 * @param data custom data
 * @param creationDate creation date
 * @tparam T user class
 */
case class AuthorizationData[T <: User](
  client: Client,
  user: Option[T],
  scope: Option[Set[String]] = None,
  givenRedirectUri: Option[String] = None,
  data: Map[String, String] = Map.empty,
  creationDate: DateTime = DateTime.now) {
  //def isExpired : Boolean = creationDate.plusSeconds(300).isBefore(DateTime.now)
  def withData(data: (String, String)*) = copy(data = data.toMap)
}
