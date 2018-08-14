package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.AuthenticatorConfiguration

abstract class DigestAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val realm: String = "digest@freeacs.com"

  val passwordRetriever: PasswordRetriever

  val noncePrivateKey: String = "verysecretkey"

  val nonceValidInMillis: Long = 10000

}

object DigestAuthenticatorConfiguration {
  def apply(retriever: PasswordRetriever): DigestAuthenticatorConfiguration =
    new DigestAuthenticatorConfiguration() {
      override val passwordRetriever: PasswordRetriever = retriever
    }
}
