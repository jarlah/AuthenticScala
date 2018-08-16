package com.github.jarlah.authenticscala.digest

object DigestAuthHeaderParser extends App {
  private val headerPrefix = "Digest "

  def extractDigestHeader(
      verb: String,
      authHeader: String
  ): Option[DigestHeader] = {
    getHeaderValue(authHeader).map(headerValue => {
      val headerDictionary = getHeaderDictionary(headerValue)
      DigestHeader(
        verb = verb,
        userName = headerDictionary.getOrElse("username", ""),
        realm = headerDictionary.getOrElse("realm", ""),
        uri = headerDictionary.getOrElse("uri", ""),
        nonce = headerDictionary.getOrElse("nonce", ""),
        requestCounter = headerDictionary.get("nc").map(_.toInt).getOrElse(0),
        clientNonce = headerDictionary.getOrElse("cnonce", ""),
        response = headerDictionary.getOrElse("response", ""),
        qualityOfProtection = headerDictionary
          .get("qop")
          .map(_.replace(" ", ""))
          .map {
            case Auth.name                       => Auth
            case qop if isAuthWithIntegrity(qop) => AuthWithIntegrity
          }
          .getOrElse(Auth),
        opaque = headerDictionary.getOrElse("opaque", "")
      )
    })
  }

  private[this] def getHeaderDictionary(
      headerValue: String
  ): Map[String, String] = {
    headerValue
      .split(",(?=([^\\\"]*\\\"[^\\\"]*\\\")*[^\\\"]*$)")
      .flatMap(pair => {
        val equalSign = pair.indexOf("=")
        if (equalSign > -1) {
          val key =
            pair.substring(0, equalSign).trim().replaceAll("\"", "").trim
          val value =
            pair.substring(equalSign + 1).trim().replaceAll("\"", "").trim
          Some((key, value))
        } else {
          None
        }
      })
      .toMap
  }

  private[this] def isAuthWithIntegrity(qop: String): Boolean =
    qop == AuthWithIntegrity.name || qop == Seq(
      Auth.name,
      AuthWithIntegrity.name
    ).mkString(",")

  private[this] def getHeaderValue(authHeader: String): Option[String] = {
    if (null == authHeader
        || authHeader.isEmpty
        || !authHeader.startsWith(headerPrefix)) {
      return None
    }
    Some(authHeader.substring(headerPrefix.length))
  }
}
