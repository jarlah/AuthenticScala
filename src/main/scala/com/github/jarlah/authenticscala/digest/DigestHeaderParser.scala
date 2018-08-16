package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.HeaderParser

object DigestHeaderParser extends HeaderParser {
  val headerPrefix = "Digest"

  def extractDigestHeader(
      verb: String,
      authHeader: String
  ): Option[DigestHeader] =
    getHeaderValue(authHeader)
      .map(getHeaderDictionary)
      .map(
        dictionary =>
          DigestHeader(
            verb = verb,
            userName = dictionary.getOrElse("username", ""),
            realm = dictionary.getOrElse("realm", ""),
            uri = dictionary.getOrElse("uri", ""),
            nonce = dictionary.getOrElse("nonce", ""),
            requestCounter = dictionary.get("nc").map(_.toInt).getOrElse(0),
            clientNonce = dictionary.getOrElse("cnonce", ""),
            response = dictionary.getOrElse("response", ""),
            qualityOfProtection = getQualityOfProtection(dictionary.get("qop")),
            opaque = dictionary.getOrElse("opaque", "")
        )
      )

  private[this] def getQualityOfProtection(qop: Option[String]) =
    qop
      .map(_.replace(" ", ""))
      .map {
        case Auth.name                       => Auth
        case qop if isAuthWithIntegrity(qop) => AuthWithIntegrity
      }
      .getOrElse(Auth)

  private[this] def getHeaderDictionary(
      headerValue: String
  ): Map[String, String] =
    headerValue
      .split(",(?=([^\\\"]*\\\"[^\\\"]*\\\")*[^\\\"]*$)")
      .filter(_.contains("="))
      .map(pair => {
        val equalSign = pair.indexOf("=")
        val key =
          pair.substring(0, equalSign).trim().replaceAll("\"", "").trim
        val value =
          pair.substring(equalSign + 1).trim().replaceAll("\"", "").trim
        (key, value)
      })
      .toMap

  private[this] def isAuthWithIntegrity(qop: String): Boolean =
    qop == AuthWithIntegrity.name || qop == Seq(
      Auth.name,
      AuthWithIntegrity.name
    ).mkString(",")
}
