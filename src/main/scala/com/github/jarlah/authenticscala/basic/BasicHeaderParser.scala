package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.HeaderParser
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicHeaderParser extends HeaderParser {
  val headerPrefix = "Basic"

  def extractBasicHeader(authHeader: String): Option[BasicHeader] =
    getHeaderValue(authHeader)
      .map(Base64Utils.decode)
      .map(_.split(":"))
      .filter(_.length == 2)
      .map(arr => (arr(0), arr(1)))
      .map(BasicHeader.tupled)

}
