package com.algd.oauth.granter

import com.algd.oauth.{TestUser, MyDataManager, OAuthSpec}
import com.algd.oauth.utils.OAuthParams

trait GranterSuite extends OAuthSpec {

  implicit val context = scala.concurrent.ExecutionContext.global

  implicit val oauthParams = new OAuthParams()

  val dataManager = new MyDataManager
  dataManager.users += ("marissa" -> ("koala", TestUser("marissa", Set("test", "test2", "test3"))))

  val baseGranter = new BaseGranter(dataManager)

  def granterFor(granter: Granter[TestUser]) = baseGranter + granter

}
