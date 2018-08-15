package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

abstract class DigestAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val noncePrivateKey: String
  val nonceValidInMillis: Long
  val realm: String
}

object DigestAuthenticatorConfiguration {
  def apply(config: Config): DigestAuthenticatorConfiguration = {
    val digestConfig = config.getConfig("authentic.digest")
    new DigestAuthenticatorConfiguration() {
      override val noncePrivateKey: String =
        digestConfig.getString("nonce.privateKey")
      override val nonceValidInMillis: Long =
        digestConfig.getLong("nonce.validInMillis")
      override val realm: String = digestConfig.getString("realm")
    }
  }
}
