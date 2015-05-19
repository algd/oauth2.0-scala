package com.algd.oauth.granter

import com.algd.oauth.data.model.{AuthorizationData, TokenResponse, Client}
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams._

class AuthorizationCodeSpec extends GranterSuite {
  dataManager.clients +=
    "acclient" -> ("client_secret", Client("Test Client", "acclient", Set("test"), Set(GrantType.AUTHORIZATION_CODE), List("http://redirect.com")))

  val acGranter = granterFor(new AuthorizationCodeGranter)

  expect[TokenResponse] ("A client should be able to obtain an access token from a valid authorization code") {
    for {
      authInfo <- dataManager.buildAuthorizationData(dataManager.clients("acclient")._2,
        Some(dataManager.users("marissa")._2),
        Some(Set("test")),
        Some("http://redirect.com/test"))
      code <- dataManager.generateAuthCode(authInfo)
      result <- acGranter(Map(CLIENT_ID -> "acclient",
        CLIENT_SECRET -> "client_secret",
        CODE -> code,
        GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
        REDIRECT_URI -> "http://redirect.com/test"))
    } yield result

  }

  expect[TokenResponse] (
    "A client should be able to obtain an access token from a valid authorization code requesting same scope") {
    dataManager.authCodes += ("validcode" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      Some(dataManager.users("marissa")._2),
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      REDIRECT_URI -> "http://redirect.com/test",
      SCOPE -> "test"))
  }

  expectError(UNAUTHORIZED_CLIENT) ("A client shouldn't be able to obtain an access token with invalid redirection uri") {
    dataManager.authCodes += ("validcode2" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      Some(dataManager.users("marissa")._2),
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode2",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      REDIRECT_URI -> "http://wrongredirect.com"))
  }

  expectError(INVALID_SCOPE) (
    "A client shouldn't be able to obtain an access token from a code with different scope") {
    dataManager.authCodes += ("validcode3" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      Some(dataManager.users("marissa")._2),
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode3",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "other"))
  }

  expectError(INVALID_GRANT) ("A client shouldn't be able to obtain a token from an invalid code") {
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "invalidcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "other"))
  }

  /*expectError(INVALID_TOKEN) ("A client shouldn't be able to obtain a token from an expired code") {
    dataManager.authCodes += ("expiredcode" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test"),
      DateTime.now -(30000*1000))) //TODO: constante
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "expiredcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "test")).onComplete(a => println(a.asInstanceOf[Failure[OAuthError]].get.error))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "expiredcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "test"))
  }*/

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token using the same code twice") {
    dataManager.authCodes += ("validcode5" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      Some(dataManager.users("marissa")._2),
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode5",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE)).flatMap{_ =>
      acGranter(Map(CLIENT_ID -> "acclient",
        CLIENT_SECRET -> "client_secret",
        CODE -> "validcode5",
        GRANT_TYPE -> GrantType.AUTHORIZATION_CODE))}
  }

}
