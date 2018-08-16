package com.github.jarlah.authenticscala

trait AuthenticatorParser {
  val headerPrefix: String

  def getHeaderValue(authHeader: String): Option[String] =
    Option(authHeader)
      .filter(_.nonEmpty)
      .filter(_.startsWith(headerPrefix))
      .map(_.substring(headerPrefix.length + 1))
}
