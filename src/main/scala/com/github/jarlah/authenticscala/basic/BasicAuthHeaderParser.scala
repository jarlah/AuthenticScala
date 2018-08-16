package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicAuthHeaderParser {
  private val headerPrefix = "Basic "

  def extractBasicHeader(authHeader: String): Option[BasicHeader] = {
    getHeaderValue(authHeader).map(headerValue => {
      val decoded  = Base64Utils.decode(headerValue)
      val userPass = decoded.split(":")
      BasicHeader(userPass(0), userPass(1))
    })
  }
  private[this] def getHeaderValue(authHeader: String): Option[String] = {
    if (authHeader == null
        || authHeader.isEmpty
        || !authHeader.startsWith(headerPrefix)
        || !authHeader.contains(":")) {
      return None
    }
    Some(authHeader.substring(headerPrefix.length))
  }
}
