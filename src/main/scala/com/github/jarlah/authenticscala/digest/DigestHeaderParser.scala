package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.HeaderParser

object DigestHeaderParser extends HeaderParser {
  val headerPrefix = "Digest"

  def extractDigestHeader(
      verb: String,
      authHeader: String
  ): Option[DigestHeader] =
    getHeaderValue(authHeader)
      .flatMap(toHeaderDictionary)
      .map(
        dict =>
          DigestHeader(
            verb = verb,
            userName = dict.getOrElse("username", ""),
            realm = dict.getOrElse("realm", ""),
            uri = dict.getOrElse("uri", ""),
            nonce = dict.getOrElse("nonce", ""),
            requestCounter = dict.get("nc").map(_.toInt).getOrElse(0),
            clientNonce = dict.getOrElse("cnonce", ""),
            response = dict.getOrElse("response", ""),
            qualityOfProtection =
              toQualityOfProtection(dict.getOrElse("qop", "")),
            opaque = dict.getOrElse("opaque", "")
        )
      )

  private[this] def toQualityOfProtection(
      qopStr: String
  ): DigestQualityOfProtection =
    Option(qopStr)
      .filter(_.nonEmpty)
      .map(_.replace(" ", ""))
      .map {
        case Auth.name                       => Auth
        case qop if isAuthWithIntegrity(qop) => AuthWithIntegrity
      }
      .getOrElse(Auth)

  private[this] def toHeaderDictionary(
      headerValue: String
  ): Option[Map[String, String]] =
    Option(headerValue)
      .filter(_.contains("="))
      .map(
        _.split(",(?=([^\\\"]*\\\"[^\\\"]*\\\")*[^\\\"]*$)")
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
      )

  private[this] def isAuthWithIntegrity(qop: String): Boolean =
    qop == AuthWithIntegrity.name || qop == Seq(
      Auth.name,
      AuthWithIntegrity.name
    ).mkString(",")
}
