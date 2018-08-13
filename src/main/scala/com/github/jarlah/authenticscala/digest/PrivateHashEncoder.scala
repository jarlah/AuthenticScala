package com.github.jarlah.authenticscala.digest

trait PrivateHashEncoder {}

object PrivateHashEncoder {

  def apply(secret: String): PrivateHashEncoder =
    new PrivateHashEncoder {}

}
