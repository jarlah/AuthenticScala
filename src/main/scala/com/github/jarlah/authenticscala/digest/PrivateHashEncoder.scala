package com.github.jarlah.authenticscala.digest
import com.github.jarlah.authenticscala.utils.DigestUtils

trait PrivateHashEncoder {
  def encode(timeInMillis: Long, remoteAddress: String): String
}

object PrivateHashEncoder {

  def apply(secret: String): PrivateHashEncoder =
    (timeInMillis: Long, remoteAddress: String) => {
      DigestUtils.md5Hex(s"$timeInMillis:$remoteAddress:$secret")
    }

}
