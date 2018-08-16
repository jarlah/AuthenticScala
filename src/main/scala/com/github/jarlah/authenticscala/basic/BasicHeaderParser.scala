package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.HeaderParser
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicHeaderParser extends HeaderParser {
  val headerPrefix = "Basic"

  def extractBasicHeader(authHeader: String): Option[BasicHeader] =
    getHeaderValue(authHeader)
      .map(Base64Utils.decode)
      .filter(_.contains(":"))
      .map(decoded => {
        val userPass = decoded.split(":")
        BasicHeader(userPass(0), userPass(1))
      })
}
