package com.algd.oauth.authorizer

import com.algd.oauth.data.model.{CodeResponse, UriResponse, Client}
import com.algd.oauth.granter.GrantType
import com.algd.oauth.utils.OAuthParams._

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
