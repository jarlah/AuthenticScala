package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

case class BasicAuthenticatorConfiguration(realm: String)
    extends AuthenticatorConfiguration

object BasicAuthenticatorConfiguration {
  def apply(config: Config): BasicAuthenticatorConfiguration = {
    val basicConfig = config.getConfig("authentic.basic")
    BasicAuthenticatorConfiguration(basicConfig.getString("realm"))
  }
}
