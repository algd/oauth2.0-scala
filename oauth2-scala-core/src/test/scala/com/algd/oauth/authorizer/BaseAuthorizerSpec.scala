package com.algd.oauth.authorizer

import com.algd.oauth.TestUser
import com.algd.oauth.data.model.{UriResponse, Client}
import com.algd.oauth.data.ValidationManager
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.utils.OAuthParams
import OAuthParams._
import com.algd.oauth.exception.OAuthError._

import scala.concurrent.{Future, ExecutionContext}

class BaseAuthorizerSpec extends AuthorizerSuite {

  case class MockedResponse(param: String)

  val testResponse = MockedResponse("OK")

  val testState = "test_state"

  val mockedAuthorizer = new Authorizer[TestUser, MockedResponse]("testName") {
    override def process(user: TestUser, client: Client)
      (implicit vm: ValidationManager[TestUser],
        params: OAuthParams,
        ec: ExecutionContext): Future[UriResponse[MockedResponse]] = {
        Future.successful(UriResponse(testUri, testResponse))
    }
  }
  dataManager.clients +=
    "client" -> ("client_secret",
      Client("Test Client",
        "client",
        Set("test"),
        Set(mockedAuthorizer.name),
        List(testUri)))


  val mAuthorizer = baseAuthorizer + mockedAuthorizer

  expectCondition[UriResponse[MockedResponse]]("Should be able to give a valid response with valid client") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> mockedAuthorizer.name))
  }(_.response == testResponse)

  expectError(INVALID_CLIENT)("Should be able to reject a request with an invalid client") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client2",
      RESPONSE_TYPE -> mockedAuthorizer.name))
  }

  expectError(UNSUPPORTED_RESPONSE_TYPE)("Should be able to reject a request for an unknown response type") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> ResponseType.TOKEN))
  }

  expectError(INVALID_REQUEST)("Should be able to reject a request without response type") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client"))
  }

  expectError(INVALID_CLIENT)("Should be able to reject a request without client id") {
    mAuthorizer(testUser, Map(
      RESPONSE_TYPE -> mockedAuthorizer.name))
  }

  expectCondition[UriResponse[MockedResponse]]("Should be able to give a valid response with valid redirect uri") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> mockedAuthorizer.name,
      REDIRECT_URI -> testUri))
  }(_.response == testResponse)

  expectError(UNAUTHORIZED_CLIENT)("Should be able to reject a request with invalid redirect uri") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> mockedAuthorizer.name,
      REDIRECT_URI -> "invalid_uri"))
  }

  expectCondition[UriResponse[MockedResponse]]("Should be able to return same state") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> mockedAuthorizer.name,
      STATE -> testState))
  }(_.state.contains(testState))

  expectCondition[OAuthError]("Should be able to return same state after an error") {
    mAuthorizer(testUser, Map(STATE -> testState))
  }(_.state.contains(testState))

  expectCondition[UriResponse[MockedResponse]]("Should be able to build a final redirect uri") {
    mAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> mockedAuthorizer.name,
      STATE -> testState))
  }(u => ResponseType.buildRedirectUri(u, '?') == testUri+"?param="+testResponse.param+"&state="+testState)

}