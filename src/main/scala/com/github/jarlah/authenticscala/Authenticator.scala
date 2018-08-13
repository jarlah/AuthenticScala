package com.github.jarlah.authenticscala

trait Authenticator[T <: AuthenticatorConfiguration] {
  val config: T
  def authenticate(
      authenticationContext: AuthenticationContext
  ): AuthenticationResult
}
