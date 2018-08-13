package com.github.jarlah.authenticscala.digest
import com.github.jarlah.authenticscala.utils.{Basic64Utils, DigestUtils}

object NonceManager {
  def generate(
      remoteAddress: String,
      privateHashEncoder: PrivateHashEncoder
  ): String = {
    val dateTimeInMilliSecondsString = System.currentTimeMillis()
    val privateHash =
      privateHashEncoder.encode(dateTimeInMilliSecondsString, remoteAddress)
    Basic64Utils.encode(s"$dateTimeInMilliSecondsString:$privateHash")
  }

  def validate(
      nonce: String,
      remoteAddress: String,
      privateHashEncoder: PrivateHashEncoder
  ): Boolean = {
    val str          = Basic64Utils.decode(nonce)
    val decodedParts = str.split(":")
    val md5EncodedString =
      privateHashEncoder.encode(decodedParts(0).toLong, remoteAddress)
    decodedParts(1).equals(md5EncodedString)
  }

  def stale(nonce: String, timeoutInMillis: Long): Boolean = {
    val decodedParts        = Basic64Utils.decode(nonce).split(":")
    val millisFromNonce     = decodedParts(0).toLong
    val currentTimeInMillis = System.currentTimeMillis()
    (millisFromNonce + timeoutInMillis) < currentTimeInMillis
  }
}
