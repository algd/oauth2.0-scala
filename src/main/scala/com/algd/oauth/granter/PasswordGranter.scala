package com.algd.oauth.granter

import com.algd.oauth.data.ValidationManager
import com.algd.oauth.data.model.{TokenResponse, Client, User}

import scala.concurrent.{Future, ExecutionContext}

class PasswordGranter[T <: User] extends GenericGranter[T] {
  def process(client: Client, params: Map[String, String])
      (implicit vm: ValidationManager[T], ec: ExecutionContext) : Future[TokenResponse] = {
    getUser(params) { (username, password) =>
      vm.validateUser(username, password).flatMap { user =>
        vm.createAccessToken(client, Some(user), getScope(params))
      }
    }
  }
}