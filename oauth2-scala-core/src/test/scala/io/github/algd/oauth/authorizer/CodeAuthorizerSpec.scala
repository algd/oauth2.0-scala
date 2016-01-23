package io.github.algd.oauth.authorizer

import io.github.algd.oauth.data.model.UriResponse
import io.github.algd.oauth.data.model.{UriResponse, CodeResponse, Client}
import io.github.algd.oauth.utils.OAuthParams
import OAuthParams._
import io.github.algd.oauth.granter.GrantType

class CodeAuthorizerSpec extends AuthorizerSuite {
  dataManager.clients +=
    "client" -> ("client_secret",
      Client("Test Client", "client", Set("test"), Set(GrantType.AUTHORIZATION_CODE), List(testUri)))

  val iAuthorizer = baseAuthorizer + new CodeAuthorizer()

  expect[UriResponse[CodeResponse]]("Should be able to give a valid response with valid client") {
    iAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> ResponseType.CODE))
  }
}
