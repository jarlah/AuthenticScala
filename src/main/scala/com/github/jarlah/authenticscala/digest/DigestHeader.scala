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
    if (null == realm
        || null == password
        || this.opaque != opaque
        || this.realm != realm) {
      return false
    }
    val hash1 = DigestUtils.md5Hex(s"$userName:$realm:$password")
    val hash2 = DigestUtils.md5Hex(s"$verb:$uri")
    response == createResponse(hash1, hash2)
  }

  private[this] def createResponse(hash1: String, hash2: String): String = {
    if (qualityOfProtection == Authentication) {
      val nc  = "%08d".format(requestCounter)
      val qop = qualityOfProtection.name
      DigestUtils.md5Hex(s"$hash1:$nonce:$nc:$clientNonce:$qop:$hash2")
    } else {
      DigestUtils.md5Hex(s"$hash1:$nonce:$hash2")
    }
  }
}
