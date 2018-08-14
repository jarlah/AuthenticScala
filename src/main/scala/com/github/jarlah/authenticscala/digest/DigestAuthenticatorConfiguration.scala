package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticatorConfiguration

import scala.concurrent.Future

abstract class DigestAuthenticatorConfiguration()
    extends AuthenticatorConfiguration {
  val realm: String = "digest@freeacs.com"

  val nonceValidInMillis: Long = 1000000

  import DigestAuthenticatorConfiguration._

  val passwordRetriever: PasswordRetriever

  val privateKey: String = "verysecretkey"

}

object DigestAuthenticatorConfiguration {
  type PasswordRetriever = String => Future[String]

  def apply(
      retriever: PasswordRetriever = _ => Future.successful("")
  ): DigestAuthenticatorConfiguration =
    new DigestAuthenticatorConfiguration {
      override val passwordRetriever: PasswordRetriever = retriever
    }
}
