package com.github.jarlah.authenticscala.digest

object DigestAuthHeaderParser {
  def extractDigestHeader(
      verb: String,
      authHeader: String
  ): Option[DigestHeader] = {

    if (null == authHeader
        || null == verb
        || authHeader.isEmpty
        || !authHeader.startsWith("Digest")
        || headerValue(authHeader).isEmpty) {
      return None
    }

    val headerDictionary: Map[String, String] = headerValue(authHeader)
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

    Some(
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
    )
  }

  private[this] def isAuthWithIntegrity(qop: String) =
    qop == AuthWithIntegrity.name || qop == Seq(
      Auth.name,
      AuthWithIntegrity.name
    ).mkString(",")

  private[this] def headerValue(authHeader: String) =
    authHeader.substring("Digest".length + 1)
}
