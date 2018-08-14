package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.AuthenticatorConfiguration

abstract class BasicAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val realm: String = "basic@freeacs.com"
}

object BasicAuthenticatorConfiguration {
  def apply(retriever: PasswordRetriever): BasicAuthenticatorConfiguration =
    new BasicAuthenticatorConfiguration() {
      override val passwordRetriever: PasswordRetriever = retriever
    }
}
