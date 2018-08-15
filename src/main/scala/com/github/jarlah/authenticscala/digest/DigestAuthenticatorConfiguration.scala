package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

case class DigestAuthenticatorConfiguration(
    encoder: PrivateHashEncoder,
    nonceTimeout: Long,
    realm: String
) extends AuthenticatorConfiguration

object DigestAuthenticatorConfiguration {
  def apply(config: Config): DigestAuthenticatorConfiguration = {
    val conf       = config.getConfig("authentic.digest")
    val privateKey = conf.getString("nonce.privateKey")
    DigestAuthenticatorConfiguration(
      PrivateHashEncoder(privateKey),
      conf.getLong("nonce.timeout"),
      conf.getString("realm")
    )
  }
}
