package com.github.jarlah.authenticscala

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.basic.BasicAuthenticator
import com.github.jarlah.authenticscala.digest.DigestAuthenticator

import scala.concurrent.{ExecutionContext, Future}
import scala.language.implicitConversions

trait Authenticator[T <: Configuration] {
  val config: T

  def authenticate(
      context: AuthenticationContext,
      passwordRetriever: PasswordRetriever
  )(implicit ec: ExecutionContext): Future[AuthenticationResult]

  def challenge(context: AuthenticationContext): Map[String, String]
}

object Authenticator {
  sealed trait Mode
  case object Digest extends Mode
  case object Basic  extends Mode

  type PasswordRetriever = String => Future[Option[String]]

  implicit def fromStringToMode(mode: String): Mode =
    mode.toLowerCase match {
      case "digest" => Digest
      case "basic"  => Basic
    }

  def authenticate(
      context: AuthenticationContext,
      retriever: PasswordRetriever,
      mode: String
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] =
    authenticate(context, retriever, mode: Mode)

  def authenticate(
      context: AuthenticationContext,
      retriever: PasswordRetriever,
      mode: Mode
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] =
    mode match {
      case Digest => DigestAuthenticator().authenticate(context, retriever)
      case Basic  => BasicAuthenticator().authenticate(context, retriever)
    }

  def challenge(
      context: AuthenticationContext,
      mode: String
  ): Map[String, String] =
    challenge(context, mode: Mode)

  def challenge(
      context: AuthenticationContext,
      mode: Mode
  ): Map[String, String] =
    mode match {
      case Digest => DigestAuthenticator.challenge(context)
      case Basic  => BasicAuthenticator.challenge(context)
    }
}
