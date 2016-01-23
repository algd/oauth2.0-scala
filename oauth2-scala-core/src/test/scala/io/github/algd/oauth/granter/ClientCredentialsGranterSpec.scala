package io.github.algd.oauth.granter

import io.github.algd.oauth.data.model.{TokenResponse, Client}
import io.github.algd.oauth.utils.OAuthParams
import OAuthParams._

class ClientCredentialsGranterSpec extends GranterSuite {
  dataManager.clients +=
    "client" -> ("client_secret", Client("Test Client", "client", Set("test"), Set(GrantType.CLIENT_CREDENTIALS), List()))

  val ccGranter = granterFor(new ClientCredentialsGranter)

  expect[TokenResponse] ("A token should be issued for valid client credentials parameters") {
    ccGranter(Map(CLIENT_ID -> "client",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.CLIENT_CREDENTIALS))
  }

}
