package com.github.jarlah.authenticscala.basic

final case class BasicHeader(username: String, password: String) {
  def credentialsMatches(secret: String): Boolean = password == secret
}
