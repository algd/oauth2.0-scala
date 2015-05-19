package com.algd.oauth.data.model

import org.joda.time.DateTime

case class Client(
  name: String,
  id: String,
  scope: Set[String],
  allowedGrants: Set[String],
  redirectUris: List[String])

trait User {
  val id: String
  val scope: Set[String]
}

case class TokenResponse(
  scope: Set[String],
  accessToken: String,
  refreshToken: Option[String] = None,
  state: Option[String] = None)

case class CodeResponse(
  scope: Set[String],
  code: String,
  redirectUri: String,
  state: Option[String] = None)

case class AuthorizationData[T <:  User](
  client: Client,
  user: Option[T],
  scope: Option[Set[String]] = None,
  givenRedirectUri: Option[String] = None,
  data: Map[String, String] = Map.empty,
  creationDate: DateTime = DateTime.now) {
  def isExpired : Boolean = creationDate.plusSeconds(300).isBefore(DateTime.now)
  def withData(data: (String, String)*) = copy(data = data.toMap)
}
