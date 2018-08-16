package com.github.jarlah.authenticscala

trait HeaderParser {
  val headerPrefix: String

  def getHeaderValue(authHeader: String): Option[String] =
    Option(authHeader)
      .filter(_.nonEmpty)
      .filter(_.startsWith(headerPrefix))
      .filter(_.length > headerPrefix.length)
      .map(_.substring(headerPrefix.length + 1))
}
