package com.algd.oauth.granter

import com.algd.oauth.TestUser
import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams
import com.algd.oauth.utils.OAuthParams._

import scala.concurrent.{Future, ExecutionContext}

class BaseGranterSpec extends GranterSuite {
  val tokenResponse = TokenResponse(Set(), "")
  val mockedGranter = new Granter[TestUser] {
    override val name: String = "testName"
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
