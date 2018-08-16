package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.HeaderParser
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicHeaderParser extends HeaderParser {
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
