package com.algd.oauth.granter

import com.algd.oauth.data.{TestUser, MyDataManager}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.utils.OAuthParams
import org.scalatest.FunSuite

import scala.concurrent.{Await, Future}
import scala.concurrent.duration._
import scala.reflect._

trait GranterSuite extends FunSuite  {

  implicit val context = scala.concurrent.ExecutionContext.global

  implicit val oauthParams = new OAuthParams()

  val dataManager = new MyDataManager
  dataManager.users += ("marissa" -> ("koala", TestUser("marissa", Set("test", "test2", "test3"))))

  val baseGranter = new BaseGranter(dataManager)

  def granterFor(granter: Granter[TestUser]) = baseGranter + granter

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
}
