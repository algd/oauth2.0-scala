package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}
import com.algd.oauth.exception.OAuthError
import com.algd.oauth.exception.OAuthError._
import com.algd.oauth.utils.OAuthParam

import scala.concurrent.{Future, ExecutionContext}

trait GenericGranter[T <: User] {
  def getCode[A](params: Map[String, String])(f: String => A) =
    params.get(OAuthParam.CODE).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, ErrorDescription(12))}

  def getRefreshToken[A](params: Map[String, String])(f: String => A) =
    params.get(OAuthParam.REFRESH_TOKEN).map(f).getOrElse{
      throw OAuthError(INVALID_REQUEST, ErrorDescription(20))}

  def getRedirectUri(params: Map[String, String]) = params.get(OAuthParam.REDIRECT_URI)

  def getClient[A](params: Map[String, String])(f: (String, String) => A) =
    (params.get(OAuthParam.CLIENT_ID), params.get(OAuthParam.CLIENT_SECRET)) match {
      case (Some(id), Some(secret)) => f(id, secret)
      case _ => throw OAuthError(INVALID_CLIENT)
    }

  def getGrantType[A](params: Map[String, String])(f: String => A) =
  params.get(OAuthParam.GRANT_TYPE).map(f).getOrElse{
    throw OAuthError(INVALID_REQUEST, ErrorDescription(5))}

  def getUser[A](params: Map[String, String])(f: (String, String) => A) =
    (params.get(OAuthParam.USERNAME), params.get(OAuthParam.PASSWORD)) match {
      case (Some(name), Some(pass)) => f(name, pass)
      case _ => throw OAuthError(INVALID_REQUEST)
    }

  def getScope(params: Map[String, String]) = params.get(OAuthParam.SCOPE).map(_.split(" ").toSet)

  def apply(params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext): Future[TokenResponse] = {
    getGrantType(params) { grantType =>
      getClient(params) { (id, secret) =>
        vm.validateClient(id, secret, grantType).flatMap(process(_, params))
      }
    }
  }

  def process(client: Client, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext) : Future[TokenResponse]
}
