package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration

import scala.concurrent.Future

abstract class DigestAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  import DigestAuthenticatorConfiguration._

  val passwordRetriever: PasswordRetriever

  val passwordVerifier: PasswordVerifier

  val privateKey: String = "verysecretkey"

}

object DigestAuthenticatorConfiguration {
  type PasswordRetriever = String => Future[String]
  type PasswordVerifier  = String => Future[Boolean]

  def apply(
      retriever: PasswordRetriever,
      verifier: PasswordVerifier
  ): DigestAuthenticatorConfiguration =
    new DigestAuthenticatorConfiguration {
      override val passwordRetriever: PasswordRetriever = retriever
      override val passwordVerifier: PasswordVerifier   = verifier
    }
}
