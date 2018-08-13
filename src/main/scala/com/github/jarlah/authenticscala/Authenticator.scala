package com.github.jarlah.authenticscala

import scala.concurrent.{ExecutionContext, Future}

trait Authenticator[T <: AuthenticatorConfiguration] {
  val config: T
  def authenticate(
      authenticationContext: AuthenticationContext
  )(implicit ec: ExecutionContext): Future[AuthenticationResult]
}
