package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.AuthenticatorParser
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicAuthHeaderParser extends AuthenticatorParser {
  val headerPrefix = "Basic "

  def extractBasicHeader(authHeader: String): Option[BasicHeader] =
    getHeaderValue(authHeader)
      .filter(_.contains(":"))
      .map(headerValue => {
        val decoded  = Base64Utils.decode(headerValue)
        val userPass = decoded.split(":")
        BasicHeader(userPass(0), userPass(1))
      })
}
