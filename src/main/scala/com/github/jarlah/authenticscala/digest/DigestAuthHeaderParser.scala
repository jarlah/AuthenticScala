package com.github.jarlah.authenticscala.digest

object DigestAuthHeaderParser {
  private val headerPrefix = "Digest "

  def extractDigestHeader(
      verb: String,
      authHeader: String
  ): Option[DigestHeader] = {
    getHeaderValue(authHeader).map(headerValue => {
      val headerDictionary: Map[String, String] = headerValue
        .split(",(?=([^\\\"]*\\\"[^\\\"]*\\\")*[^\\\"]*$)")
        .map(pair => {
          val firstEqualIndex = pair.indexOf("=")
          val key =
            pair.substring(0, firstEqualIndex).trim().replaceAll("\"", "").trim
          val value =
            pair.substring(firstEqualIndex + 1).trim().replaceAll("\"", "").trim
          (key, value)
        })
        .toMap
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

  private[this] def isAuthWithIntegrity(qop: String) =
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
