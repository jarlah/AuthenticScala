package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

final case class DigestAuthenticatorConfiguration(
    encoder: PrivateHashEncoder,
    nonceTimeout: Long,
    realm: String
) extends AuthenticatorConfiguration

object DigestAuthenticatorConfiguration {
  def apply(config: Config): DigestAuthenticatorConfiguration = {
    val conf         = config.getConfig("authentic.digest")
    val realm        = conf.getString("realm")
    val nonceKey     = conf.getString("nonce.privateKey")
    val nonceTimeout = conf.getLong("nonce.timeout")
    val nonceEncoder = PrivateHashEncoder(nonceKey)
    DigestAuthenticatorConfiguration(nonceEncoder, nonceTimeout, realm)
  }
}
