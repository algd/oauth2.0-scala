package com.algd.oauth.granter

import com.algd.oauth.data.{TestUser, MyValidationManager}
import com.algd.oauth.data.model.{AuthorizationData, TokenResponse, Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParams
import org.scalatest.FunSuite
import com.algd.oauth.utils.OAuthParams._
import scala.concurrent.{Future, Await}
import scala.concurrent.duration._
import scala.reflect.ClassTag
import scala.reflect.classTag
import org.joda.time.DateTime

class GranterSpec extends FunSuite {
  import scala.concurrent.ExecutionContext.Implicits.global
  implicit val dataManager = new MyValidationManager
  implicit val oauthParams = new OAuthParams()
  dataManager.clients +=
    "ccclient" -> ("client_secret", Client("Test Client", "ccclient", Set("test"), Set(GrantType.CLIENT_CREDENTIALS), List()))
  dataManager.clients +=
    "pclient" -> ("client_secret", Client("Test Client", "pclient", Set("test", "test3"), Set(GrantType.PASSWORD), List()))
  dataManager.clients +=
    "acclient" -> ("client_secret", Client("Test Client", "acclient", Set("test"), Set(GrantType.AUTHORIZATION_CODE), List("http://redirect.com")))
  dataManager.clients +=
    "rtclient" -> ("client_secret", Client("Test Client", "rtclient", Set("test", "test3"), Set(GrantType.REFRESH_TOKEN), List("http://redirect.com")))
  dataManager.users += ("marissa" -> ("koala", TestUser("marissa", Set("test", "test2", "test3"))))

  val baseGranter = new BaseGranter[TestUser]()
  val ccGranter = baseGranter + new ClientCredentialsGranter[TestUser]
  val acGranter = baseGranter + new AuthorizationCodeGranter[TestUser]
  val pGranter = baseGranter + new PasswordGranter[TestUser]
  val rtGranter = baseGranter + new RefreshTokenGranter[TestUser]

  def expectCondition[T:ClassTag](title: String)(f: => Future[Any])(cond: T => Boolean): Unit = test(title) {
    val res = Await.result(f.recover{ case e:Throwable => e }, 3.seconds)
    if (classTag[T].runtimeClass != res.getClass) {
      fail("Unexpected result " + res.asInstanceOf[OAuthError].printStackTrace())
    } else if (!cond(res.asInstanceOf[T]))
      fail("Requirement failed for " + res)
  }

  def expectError(error: String)(title: String)(f: => Future[Any]): Unit =
    expectCondition[OAuthError](title)(f){case OAuthError(err, _) => err == error}

  def expect[T:ClassTag](title: String)(f: => Future[Any]): Unit =
    expectCondition[T](title)(f){_:T => true}

  //Tests

  expect[TokenResponse] ("A token should be issued for valid client credentials parameters") {
    ccGranter(Map(CLIENT_ID -> "ccclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.CLIENT_CREDENTIALS))
  }

  expectError(UNAUTHORIZED_CLIENT) ("A client shouldn't be able to use not allowed grant types") {
    ccGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.CLIENT_CREDENTIALS))
  }

  expectError(INVALID_CLIENT) ("A client shouldn't be able to authenticate with incorrect secret") {
    ccGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "secret",
      GRANT_TYPE -> GrantType.CLIENT_CREDENTIALS))
  }

  expect[TokenResponse] ("A client should be able to obtain an access token from a valid authorization code") {
    dataManager.generateAuthCode(dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test")).flatMap { code =>
      acGranter(Map(CLIENT_ID -> "acclient",
        CLIENT_SECRET -> "client_secret",
        CODE -> code,
        GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
        REDIRECT_URI -> "http://redirect.com/test"))
    }
  }

  expect[TokenResponse] (
    "A client should be able to obtain an access token from a valid authorization code requesting same scope") {
    dataManager.authCodes += ("validcode" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      REDIRECT_URI -> "http://redirect.com/test",
      SCOPE -> "test"))
  }

  expectError(UNAUTHORIZED_CLIENT) ("A client shouldn't be able to obtain an access token with invalid redirection uri") {
    dataManager.authCodes += ("validcode2" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode2",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      REDIRECT_URI -> "http://wrongredirect.com"))
  }

  expectError(INVALID_SCOPE) (
    "A client shouldn't be able to obtain an access token from a code with different scope") {
    dataManager.authCodes += ("validcode3" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode3",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "other"))
  }

  expectError(INVALID_GRANT) ("A client shouldn't be able to obtain a token from an invalid code") {
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "invalidcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "other"))
  }

  /*expectError(INVALID_TOKEN) ("A client shouldn't be able to obtain a token from an expired code") {
    dataManager.authCodes += ("expiredcode" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test"),
      DateTime.now -(30000*1000))) //TODO: constante
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "expiredcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "test")).onComplete(a => println(a.asInstanceOf[Failure[OAuthError]].get.error))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "expiredcode",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE,
      SCOPE -> "test"))
  }*/

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token using the same code twice") {
    dataManager.authCodes += ("validcode5" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      Some("http://redirect.com/test")))
    acGranter(Map(CLIENT_ID -> "acclient",
      CLIENT_SECRET -> "client_secret",
      CODE -> "validcode5",
      GRANT_TYPE -> GrantType.AUTHORIZATION_CODE)).flatMap{_ =>
      acGranter(Map(CLIENT_ID -> "acclient",
        CLIENT_SECRET -> "client_secret",
        CODE -> "validcode5",
        GRANT_TYPE -> GrantType.AUTHORIZATION_CODE))}
  }

  expect[TokenResponse] (
    "A client should be able to obtain an access token from a valid user/password") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marissa",
      PASSWORD -> "koala",
      SCOPE -> "test"))
  }

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token from an invalid user/password") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marisa",
      PASSWORD -> "koala",
      SCOPE -> "test"))
  }

  expectError(INVALID_REQUEST) (
    "A client shouldn't be able to obtain an access token without user/password") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      SCOPE -> "test"))
  }

  expectError(INVALID_SCOPE) (
    "A client shouldn't be able to ask for a scope that the client doesn't got but the user") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marissa",
      PASSWORD -> "koala",
      SCOPE -> "test2"))
  }

  expectCondition[TokenResponse] (
    "The scope should be the intersection of requested scope, client scope and user scope") {
    pGranter(Map(CLIENT_ID -> "pclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.PASSWORD,
      USERNAME -> "marissa",
      PASSWORD -> "koala",
      SCOPE -> "test2 test3"))
  } { t => t.scope == Set("test3") }

  expect[TokenResponse] (
    "A client should be able to obtain an access token from a valid refresh token") {
    dataManager.refTokenDatas += ("refreshtoken1" -> AuthorizationData(
      dataManager.clients("rtclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test"))))
    rtGranter(Map(CLIENT_ID -> "rtclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.REFRESH_TOKEN,
      REFRESH_TOKEN -> "refreshtoken1"))
  }

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token from a invalid refresh token") {
    rtGranter(Map(CLIENT_ID -> "rtclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.REFRESH_TOKEN,
      REFRESH_TOKEN -> "refreshtoken2"))
  }

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token from a valid refresh token that belongs to another client") {
    dataManager.refTokenDatas += ("refreshtoken3" -> AuthorizationData(
      dataManager.clients("acclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test"))))
    rtGranter(Map(CLIENT_ID -> "rtclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.REFRESH_TOKEN,
      REFRESH_TOKEN -> "refreshtoken3"))
  }

  expectError(INVALID_GRANT) (
    "A client shouldn't be able to obtain an access token from an expired refresh token") {
    dataManager.refTokenDatas += ("refreshtoken4" -> AuthorizationData(
      dataManager.clients("rtclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test")),
      creationDate = DateTime.now.minusSeconds(40000)))
    rtGranter(Map(CLIENT_ID -> "rtclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.REFRESH_TOKEN,
      REFRESH_TOKEN -> "refreshtoken4"))
  }

  expectError(INVALID_REQUEST) (
    "A client shouldn't be able to obtain an access token without refresh token") {
    rtGranter(Map(CLIENT_ID -> "rtclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.REFRESH_TOKEN))
  }

  /*expectError(INVALID_SCOPE) ( //TODO: different? more?
    "A client shouldn't be able to obtain an access token with a refresh token requesting different scope") {
    dataManager.refTokenDatas += ("refreshtoken5" -> AuthorizationData(
      dataManager.clients("rtclient")._2,
      dataManager.users("marissa")._2,
      Some(Set("test"))))
    rtGranter(Map(CLIENT_ID -> "rtclient",
      CLIENT_SECRET -> "client_secret",
      GRANT_TYPE -> GrantType.REFRESH_TOKEN,
      REFRESH_TOKEN -> "refreshtoken5",
      SCOPE -> "test3"))
  }*/
}