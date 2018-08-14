package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}

import scala.concurrent.{ExecutionContext, Future}

object BasicAuthenticator {
  def apply(retriever: PasswordRetriever): BasicAuthenticator =
    BasicAuthenticator(BasicAuthenticatorConfiguration(retriever))

  def challenge(context: AuthenticationContext): Map[String, String] =
    BasicAuthenticator(BasicAuthenticatorConfiguration(Future.successful))
      .challenge(context)
}

final case class BasicAuthenticator(config: BasicAuthenticatorConfiguration)
    extends Authenticator[BasicAuthenticatorConfiguration] {

  def authenticate(context: AuthenticationContext)(
      implicit ec: ExecutionContext
  ): Future[AuthenticationResult] = {
    val baStr =
      context.httpHeaders
        .getOrElse("Authorization", "")
        .replaceFirst("Basic ", "")
    val decoded  = new sun.misc.BASE64Decoder().decodeBuffer(baStr)
    val userPass = new String(decoded).split(":")
    config.passwordRetriever
      .apply(userPass(0))
      .map {
        case userSecret
            if userPass.size > 1 && userSecret.equals(userPass(1)) =>
          AuthenticationResult(
            success = true,
            principal = Some(userPass(0)),
            errorMessage = None
          )
        case _ =>
          AuthenticationResult(
            success = false,
            None,
            Some("Wrong username or password")
          )
      }
      .recover {
        case _: Throwable =>
          AuthenticationResult(
            success = false,
            None,
            Some("Unable to retrieve password")
          )
      }
  }

  def challenge(context: AuthenticationContext): Map[String, String] =
    Map("WWW-Authenticate" -> s"""Basic realm="${config.realm}"""")

}
