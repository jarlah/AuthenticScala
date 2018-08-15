package com.github.jarlah.authenticscala.digest
import com.github.jarlah.authenticscala.utils.DigestUtils

trait OpaqueManager {}

object OpaqueManager {
  def getOpaque(nonce: String): String = DigestUtils.md5Hex(nonce)
}
