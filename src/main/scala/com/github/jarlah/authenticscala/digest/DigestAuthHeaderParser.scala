package com.github.jarlah.authenticscala.digest

object DigestAuthHeaderParser {
  def extractDigestHeader(
      verb: String,
      authHeader: String
  ): Either[String, DigestHeader] = {

    if (null == authHeader) {
      return Left("Missing authHeader")
    }

    if (null == verb) {
      return Left("Missing verb")
    }

    if (authHeader.isEmpty || !authHeader.startsWith("Digest")) {
      return Left(
        "AuthHeader cannot be null or empty OR does not start with Digest"
      )
    }

    val keyValuePairs = authHeader.substring(7)
    if (keyValuePairs.isEmpty) {
      return Left(
        "Authorization header did not contain any data other than Digest"
      )
    }

    val headerDictionary: Map[String, String] = keyValuePairs
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
      nonce = headerDictionary.getOrElse("cnonce", ""),
      requestCounter = headerDictionary.get("nc").map(_.toInt).getOrElse(0),
      clientNonce = headerDictionary.getOrElse("cnonce", ""),
      response = headerDictionary.getOrElse("response", ""),
      qualityOfProtection = headerDictionary
        .get("qop")
        .map(_.replace(" ", ""))
        .map {
          case "auth"          => Authentication
          case "auth-int"      => AuthenticationWithIntegrity
          case "auth,auth-int" => AuthenticationWithIntegrity
        }
        .getOrElse(Authentication),
      opaque = headerDictionary.getOrElse("opaque", "")
    )
  }
}
