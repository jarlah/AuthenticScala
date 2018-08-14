package com.github.jarlah.authenticscala

import com.github.jarlah.authenticscala.basic.BasicAuthenticator
import com.github.jarlah.authenticscala.digest.DigestAuthenticator

import scala.concurrent.{ExecutionContext, Future}

trait Authenticator[T <: AuthenticatorConfiguration] {
  val config: T
  def authenticate(context: AuthenticationContext)(
      implicit ec: ExecutionContext
  ): Future[AuthenticationResult]

  def challenge(context: AuthenticationContext): Map[String, String]
}

object Authenticator {
  sealed trait Mode
  case object Digest extends Mode
  case object Basic  extends Mode

  type PasswordRetriever = String => Future[String]

  def authenticate(
      context: AuthenticationContext,
      retriever: PasswordRetriever,
      mode: Mode
  )(
      implicit ec: ExecutionContext
  ): Future[AuthenticationResult] = {
    mode match {
      case Digest => DigestAuthenticator(retriever).authenticate(context)
      case Basic  => BasicAuthenticator(retriever).authenticate(context)
    }
  }

  def challenge(
      context: AuthenticationContext,
      mode: Mode
  ): Map[String, String] =
    mode match {
      case Digest => DigestAuthenticator.challenge(context)
      case Basic  => BasicAuthenticator.challenge(context)
    }
}
