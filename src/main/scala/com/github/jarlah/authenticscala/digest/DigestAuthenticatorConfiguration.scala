package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration

import scala.concurrent.Future

trait DigestAuthenticatorConfiguration extends AuthenticatorConfiguration {
  import DigestAuthenticatorConfiguration._

  val passwordRetriever: PasswordRetriever

  val privateKey: String = "verysecretkey"

}

object DigestAuthenticatorConfiguration {
  type PasswordRetriever = String => Future[String]

  def apply(retriever: PasswordRetriever): DigestAuthenticatorConfiguration =
    new DigestAuthenticatorConfiguration {
      override val passwordRetriever = retriever
    }
}
