package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

abstract class DigestAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val encoder: PrivateHashEncoder
  val nonceTimeout: Long
  val realm: String
}

object DigestAuthenticatorConfiguration {
  def apply(config: Config): DigestAuthenticatorConfiguration = {
    val conf = config.getConfig("authentic.digest")
    new DigestAuthenticatorConfiguration() {
      override val nonceTimeout: Long = conf.getLong("nonce.timeout")
      override val realm: String      = conf.getString("realm")
      private val noncePrivateKey     = conf.getString("nonce.privateKey")
      override val encoder            = PrivateHashEncoder(noncePrivateKey)
    }
  }
}
