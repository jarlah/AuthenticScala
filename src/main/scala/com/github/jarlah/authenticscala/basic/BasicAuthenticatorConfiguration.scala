package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.AuthenticatorConfiguration
import com.typesafe.config.Config

abstract class BasicAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val realm: String
}

object BasicAuthenticatorConfiguration {
  def apply(
      config: Config,
      retriever: PasswordRetriever
  ): BasicAuthenticatorConfiguration = {
    val basicConfig = config.getConfig("basic")
    new BasicAuthenticatorConfiguration() {
      override val passwordRetriever: PasswordRetriever = retriever
      override val realm: String                        = basicConfig.getString("realm")
    }
  }
}
