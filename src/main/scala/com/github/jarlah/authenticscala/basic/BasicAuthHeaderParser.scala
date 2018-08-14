package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.utils.Base64Utils

object BasicAuthHeaderParser {
  def extractBasicHeader(authHeader: String): Either[String, BasicHeader] = {
    if (authHeader.isEmpty || !authHeader.startsWith("Basic")) {
      return Left(
        "AuthHeader cannot be null or empty OR does not start with Basic"
      )
    }
    val baStr    = authHeader.substring(6)
    val decoded  = Base64Utils.decode(baStr)
    val userPass = decoded.split(":")
    if (userPass.size == 2) {
      Right(BasicHeader(userPass(0), userPass(1)))
    } else {
      Left("Invalid authorization header")
    }
  }
}
