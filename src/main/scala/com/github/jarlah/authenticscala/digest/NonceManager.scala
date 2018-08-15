package com.github.jarlah.authenticscala.digest
import com.github.jarlah.authenticscala.utils.Base64Utils

object NonceManager {
  def generate(remoteAddress: String, encoder: PrivateHashEncoder): String = {
    val currentTime = System.currentTimeMillis()
    val privateHash = encoder.encode(currentTime, remoteAddress)
    Base64Utils.encode(s"$currentTime:$privateHash")
  }

  def validate(
      nonce: String,
      remoteAddress: String,
      encoder: PrivateHashEncoder
  ): Boolean = {
    val str              = Base64Utils.decode(nonce)
    val decodedParts     = str.split(":")
    val timestampPart    = decodedParts(0).toLong
    val md5EncodedString = encoder.encode(timestampPart, remoteAddress)
    val encodedPart      = decodedParts(1)
    encodedPart == md5EncodedString
  }

  def stale(nonce: String, timeoutInMillis: Long): Boolean = {
    val decodedParts  = Base64Utils.decode(nonce).split(":")
    val timeFromNonce = decodedParts(0).toLong
    val currentTime   = System.currentTimeMillis()
    (timeFromNonce + timeoutInMillis) < currentTime
  }
}
