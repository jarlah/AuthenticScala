package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

final case class BasicAuthenticatorConfiguration(realm: String)
    extends AuthenticatorConfiguration

object BasicAuthenticatorConfiguration {
  def apply(config: Config): BasicAuthenticatorConfiguration =
    BasicAuthenticatorConfiguration(config.getString("authentic.basic.realm"))
}
