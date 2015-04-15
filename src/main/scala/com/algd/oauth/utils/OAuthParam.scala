package com.algd.oauth.utils

/**
 *  Contains OAuth2 parameter names
 */
object OAuthParam {
  val GRANT_TYPE = "grant_type"
  val RESPONSE_TYPE = "response_type"
  val CLIENT_ID = "client_id"
  val CLIENT_SECRET = "client_secret"
  val SCOPE = "scope"
  val STATE = "state"
  val CODE = "code"
  val REDIRECT_URI = "redirect_uri"
  val USERNAME = "username"
  val PASSWORD = "password"
  val REFRESH_TOKEN = "refresh_token"
  val ACCESS_TOKEN = "access_token"
  /// not standard
  val AUTHENTICITY_TOKEN = "authenticity_token"
}