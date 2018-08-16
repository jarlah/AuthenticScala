package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.Configuration
import com.typesafe.config.Config

final case class DigestConfiguration(
    encoder: PrivateHashEncoder,
    nonceTimeout: Long,
    realm: String
) extends Configuration

object DigestConfiguration {
  def apply(config: Config): DigestConfiguration = {
    val conf         = config.getConfig("authentic.digest")
    val realm        = conf.getString("realm")
    val nonceKey     = conf.getString("nonce.privateKey")
    val nonceTimeout = conf.getLong("nonce.timeout")
    val nonceEncoder = PrivateHashEncoder(nonceKey)
    DigestConfiguration(nonceEncoder, nonceTimeout, realm)
  }
}
