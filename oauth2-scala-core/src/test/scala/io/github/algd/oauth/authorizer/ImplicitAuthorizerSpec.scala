package io.github.algd.oauth.authorizer

import io.github.algd.oauth.data.model.UriResponse
import io.github.algd.oauth.data.model.{UriResponse, TokenResponse, Client}
import io.github.algd.oauth.utils.OAuthParams
import OAuthParams._
import io.github.algd.oauth.granter.GrantType

class ImplicitAuthorizerSpec extends AuthorizerSuite {

  dataManager.clients +=
    "client" -> ("client_secret",
      Client("Test Client", "client", Set("test"), Set(GrantType.IMPLICIT), List(testUri)))

  val iAuthorizer = baseAuthorizer + new ImplicitAuthorizer()

  expect[UriResponse[TokenResponse]]("Should be able to give a valid response with valid client") {
    iAuthorizer(testUser, Map(
      CLIENT_ID -> "client",
      RESPONSE_TYPE -> ResponseType.TOKEN))
  }
}
