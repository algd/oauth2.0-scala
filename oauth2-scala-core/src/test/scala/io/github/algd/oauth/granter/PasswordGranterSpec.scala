package io.github.algd.oauth.granter

import io.github.algd.oauth.exception.OAuthError
import OAuthError._
import io.github.algd.oauth.utils.OAuthParams
import OAuthParams._
import io.github.algd.oauth.data.model.{Client, TokenResponse}

class PasswordGranterSpec extends GranterSuite {
  dataManager.clients +=
    "pclient" -> ("client_secret", Client("Test Client", "pclient", Set("test", "test3"), Set(GrantType.PASSWORD), List()))

  val pGranter = granterFor(new PasswordGranter)

  expect[TokenResponse] (
    "A client should be able to obtain an access token from a valid user/password") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marissa",
      PASSWORD -> "koala",
      SCOPE -> "test"))
  }

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token from an invalid user/password") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marisa",
      PASSWORD -> "koala",
      SCOPE -> "test"))
  }

  expectError(INVALID_REQUEST) (
    "A client shouldn't be able to obtain an access token without user/password") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      SCOPE -> "test"))
  }

  expectError(INVALID_SCOPE) (
    "A client shouldn't be able to ask for a scope that the client doesn't got but the user") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marissa",
      PASSWORD -> "koala",
      SCOPE -> "test2"))
  }

  expectCondition[TokenResponse] (
    "The scope should be the intersection of requested scope, client scope and user scope") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marissa",
      PASSWORD -> "koala",
      SCOPE -> "test2 test3"))
  } { _.scope == "test3" }
}
