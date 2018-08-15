package com.github.jarlah.authenticscala.digest
import com.github.jarlah.authenticscala.utils.DigestUtils

case class DigestHeader(
    verb: String,
    userName: String,
    realm: String,
    nonce: String,
    uri: String,
    qualityOfProtection: DigestQualityOfProtection,
    requestCounter: Int,
    clientNonce: String,
    response: String,
    opaque: String
) {

  def matchesCredentials(
      realm: String,
      opaque: String,
      password: String
  ): Boolean = {
    if (null == realm) {
      throw new IllegalArgumentException("realm")
    }
    if (null == password) {
      throw new IllegalArgumentException("password")
    }
    if (this.opaque != opaque) {
      return false
    }
    if (this.realm != realm) {
      return false
    }
    val hash1 = DigestUtils.md5Hex(s"$userName:$realm:$password")
    val hash2 = DigestUtils.md5Hex(s"$verb:$uri")
    response == createResponse(hash1, hash2)
  }

  private def createResponse(hash1: String, hash2: String): String = {
    if (qualityOfProtection == Authentication) {
      val nc  = "%08d".format(requestCounter)
      val qop = qualityOfProtection.name
      DigestUtils.md5Hex(s"$hash1:$nonce:$nc:$clientNonce:$qop:$hash2")
    } else {
      DigestUtils.md5Hex(s"$hash1:$nonce:$hash2")
    }
  }
}

object DigestHeader {
  def apply(
      verb: String,
      userName: String,
      realm: String,
      nonce: String,
      uri: String,
      qualityOfProtection: DigestQualityOfProtection,
      requestCounter: Int,
      clientNonce: String,
      response: String,
      opaque: String
  ): Either[String, DigestHeader] = {
    if (AuthenticationWithIntegrity == qualityOfProtection)
      return Left("auth-int is not currently supported")

    if (null == verb)
      return Left("verb")

    Right(
      new DigestHeader(
        verb,
        userName,
        realm,
        nonce,
        uri,
        qualityOfProtection,
        requestCounter,
        clientNonce,
        response,
        opaque
      )
    )
  }
}
