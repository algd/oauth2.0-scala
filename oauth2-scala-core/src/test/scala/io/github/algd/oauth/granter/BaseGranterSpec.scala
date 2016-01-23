package io.github.algd.oauth.granter

import io.github.algd.oauth.TestUser
import io.github.algd.oauth.data.ValidationManager
import io.github.algd.oauth.data.model.{TokenResponse, Client}
import io.github.algd.oauth.exception.OAuthError
import OAuthError._
import io.github.algd.oauth.utils.OAuthParams
import OAuthParams._
import io.github.algd.oauth.exception.OAuthError
import io.github.algd.oauth.utils.OAuthParams

import scala.concurrent.{Future, ExecutionContext}

class BaseGranterSpec extends GranterSuite {
  val tokenResponse = TokenResponse("", "")
  val mockedGranter = new Granter[TestUser]("testName") {
    override def process(client: Client)(
      implicit vm: ValidationManager[TestUser],
      params: OAuthParams,
      ec: ExecutionContext): Future[TokenResponse] = Future.successful(tokenResponse)
  }

  val mGranter = granterFor(mockedGranter)
  val state = "test_state"

  dataManager.clients +=
    "client" -> ("client_secret", Client("Test Client", "client", Set("test"), Set(mockedGranter.name), List()))

  expect[TokenResponse] ("A token should be issued for valid client credentials parameters") {
    mGranter(Map(CLIENT_ID -> "client",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> mockedGranter.name))
  }

  expectError(UNAUTHORIZED_CLIENT) ("A client shouldn't be able to use not allowed grant types") {
    (mGranter + new ClientCredentialsGranter)(Map(CLIENT_ID -> "client",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.CLIENT_CREDENTIALS))
  }

  expectError(INVALID_CLIENT) ("A client shouldn't be able to authenticate with incorrect secret") {
    mGranter(Map(CLIENT_ID -> "client",
      CLIENT_SECRET -> "secret",
      GRANT_TYPE -> mockedGranter.name))
  }

  expectError(UNSUPPORTED_GRANT_TYPE) ("A token should not be issued through an unsupported grant type") {
    baseGranter(Map(CLIENT_ID -> "client",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.CLIENT_CREDENTIALS))
  }

  expectCondition[TokenResponse] ("A token should be issued giving back the same state") {
    mGranter(Map(CLIENT_ID -> "client",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> mockedGranter.name,
      STATE -> state))
  } {_.state.contains(state)}

  expectCondition[OAuthError] ("An error should be thrown giving back the same state") {
    mGranter(Map(STATE -> state))
  } {_.state.contains(state)}

}
