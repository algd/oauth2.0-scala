package com.algd.oauth.authorizer

import com.algd.oauth.data.model.{TokenResponse, UriResponse, Client}
import com.algd.oauth.granter.GrantType
import com.algd.oauth.utils.OAuthParams._

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
