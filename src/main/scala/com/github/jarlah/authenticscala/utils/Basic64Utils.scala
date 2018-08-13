package com.github.jarlah.authenticscala.utils

object Basic64Utils {

  def encode(text: String): String =
    new String(java.util.Base64.getEncoder.encode(text.getBytes()))

  def decode(base64: String): String =
    new String(java.util.Base64.getDecoder.decode(base64))
}
