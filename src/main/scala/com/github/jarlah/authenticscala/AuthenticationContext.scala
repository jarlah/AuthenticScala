package com.github.jarlah.authenticscala

final case class AuthenticationContext(
    httpMethod: String,
    httpUri: String,
    httpHeaders: Map[String, String],
    remoteAddress: String
) {
  def getAuthHeader: String = httpHeaders.getOrElse("Authorization", "")
}
