package io.github.algd.oauth

import io.github.algd.oauth.exception.OAuthError
import org.scalatest.FunSuite

import scala.concurrent.{ExecutionContext, Await, Future}
import scala.concurrent.duration._
import scala.reflect._

class OAuthSpec extends FunSuite {

  def expectCondition[T:ClassTag](title: String)
    (f: => Future[Any])(cond: T => Boolean)
    (implicit ec: ExecutionContext): Unit = test(title) {
    val res = Await.result(f.recover{ case e:Throwable => e }, 3.seconds)
    if (classTag[T].runtimeClass != res.getClass) {
      fail("Unexpected result " + res.asInstanceOf[OAuthError].printStackTrace())
    } else if (!cond(res.asInstanceOf[T]))
      fail("Requirement failed for " + res)
  }

  def expectError(error: String)(title: String)(f: => Future[Any])
    (implicit ec: ExecutionContext): Unit =
    expectCondition[OAuthError](title)(f){case OAuthError(err, _, _) => err == error}

  def expect[T:ClassTag](title: String)(f: => Future[Any])
    (implicit ec: ExecutionContext): Unit =
    expectCondition[T](title)(f){_:T => true}
}
