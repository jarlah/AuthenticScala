package com.github.jarlah.authenticscala

import com.github.jarlah.authenticscala.digest.DigestAuthenticatorConfiguration.PasswordRetriever
import com.github.jarlah.authenticscala.digest.{
  DigestAuthenticator,
  DigestAuthenticatorConfiguration
}

import scala.concurrent.{ExecutionContext, Future}

trait Authenticator[T <: AuthenticatorConfiguration] {
  val config: T
  def authenticate(
      authenticationContext: AuthenticationContext
  )(implicit ec: ExecutionContext): Future[AuthenticationResult]
}

object Authenticator {
  sealed trait AuthenticatorMode
  case object Digest extends AuthenticatorMode

  def authenticate(
      context: AuthenticationContext,
      retriever: PasswordRetriever,
      mode: AuthenticatorMode
  )(
      implicit ec: ExecutionContext
  ): Future[AuthenticationResult] = {
    mode match {
      case Digest =>
        DigestAuthenticator(DigestAuthenticatorConfiguration(retriever))
          .authenticate(context)
    }
  }

  def challenge(
      context: AuthenticationContext,
      mode: AuthenticatorMode
  ): Map[String, String] =
    mode match {
      case Digest =>
        Map(
          DigestAuthenticator(DigestAuthenticatorConfiguration())
            .challenge(context)
        )
    }
}
