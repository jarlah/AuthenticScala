package com.github.jarlah.authenticscala
import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever

trait AuthenticatorConfiguration {
  val realm: String
  val passwordRetriever: PasswordRetriever
}
