package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicAuthHeaderParser {
  def extractBasicHeader(authHeader: String): Option[BasicHeader] = {
    if (authHeader == null
        || authHeader.isEmpty
        || !authHeader.startsWith("Basic")
        || headerValue(authHeader).isEmpty) {
      return None
    }
    val base64Str = headerValue(authHeader)
    val decoded   = Base64Utils.decode(base64Str)
    val userPass  = decoded.split(":")
    if (userPass.size == 2) {
      Some(BasicHeader(userPass(0), userPass(1)))
    } else {
      None
    }
  }
  private[this] def headerValue(authHeader: String) =
    authHeader.substring("Basic".length + 1)
}
