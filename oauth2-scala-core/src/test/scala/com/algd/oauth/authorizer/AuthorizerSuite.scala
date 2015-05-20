package com.algd.oauth.authorizer

import com.algd.oauth.OAuthSpec
import com.algd.oauth.data.{TestUser, MyDataManager}
import com.algd.oauth.utils.OAuthParams

trait AuthorizerSuite extends OAuthSpec {
  implicit val context = scala.concurrent.ExecutionContext.global

  implicit val oauthParams = new OAuthParams()

  val dataManager = new MyDataManager
  val testUser = TestUser("marissa", Set("test", "test2", "test3"))
  dataManager.users += ("marissa" -> ("koala", testUser))

  val baseAuthorizer = new BaseAuthorizer(dataManager)

  val testUri = "http://redirect.uri.com"
}
