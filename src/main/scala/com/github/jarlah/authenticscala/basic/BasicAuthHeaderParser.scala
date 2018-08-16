package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicAuthHeaderParser {
  private val headerPrefix = "Basic "

  def extractBasicHeader(authHeader: String): Option[BasicHeader] = {
    getHeaderValue(authHeader).flatMap(headerValue => {
      val decoded  = Base64Utils.decode(headerValue)
      val userPass = decoded.split(":")
      if (userPass.size == 2) {
        Some(BasicHeader(userPass(0), userPass(1)))
      } else {
        None
      }
    })
  }
  private[this] def getHeaderValue(authHeader: String): Option[String] = {
    if (authHeader == null
        || authHeader.isEmpty
        || !authHeader.startsWith(headerPrefix)) {
      return None
    }
    Some(authHeader.substring(headerPrefix.length))
  }
}
