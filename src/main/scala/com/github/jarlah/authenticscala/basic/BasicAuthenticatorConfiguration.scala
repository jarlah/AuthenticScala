package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

abstract class BasicAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val realm: String
}

object BasicAuthenticatorConfiguration {
  def apply(config: Config): BasicAuthenticatorConfiguration = {
    val basicConfig = config.getConfig("authentic.basic")
    new BasicAuthenticatorConfiguration() {
      override val realm: String = basicConfig.getString("realm")
    }
  }
}
