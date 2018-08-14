package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

abstract class DigestAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val passwordRetriever: PasswordRetriever
  val noncePrivateKey: String
  val nonceValidInMillis: Long
  val realm: String
}

object DigestAuthenticatorConfiguration {
  def apply(
      config: Config,
      retriever: PasswordRetriever
  ): DigestAuthenticatorConfiguration = {
    val digestConfig = config.getConfig("digest")
    new DigestAuthenticatorConfiguration() {
      override val passwordRetriever: PasswordRetriever = retriever
      override val noncePrivateKey: String =
        digestConfig.getString("nonce.privateKey")
      override val nonceValidInMillis: Long =
        digestConfig.getLong("nonce.validInMillis")
      override val realm: String = digestConfig.getString("realm")
    }
  }
}
