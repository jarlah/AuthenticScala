package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}
import com.typesafe.config.ConfigFactory

import scala.concurrent.{ExecutionContext, Future}

object BasicAuthenticator {
  val config = BasicAuthenticatorConfiguration(ConfigFactory.load)

  def apply(): BasicAuthenticator =
    BasicAuthenticator(config)

  def challenge(context: AuthenticationContext): Map[String, String] =
    BasicAuthenticator().challenge(context)
}

final case class BasicAuthenticator(config: BasicAuthenticatorConfiguration)
    extends Authenticator[BasicAuthenticatorConfiguration] {

  def authenticate(
      context: AuthenticationContext,
      passwordRetriever: PasswordRetriever
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] =
    BasicAuthHeaderParser.extractBasicHeader(context.getAuthHeader) match {
      case Some(basicHeader) =>
        passwordRetriever
          .apply(basicHeader.username)
          .map {
            case userSecret if userSecret == basicHeader.password =>
              AuthenticationResult(
                success = true,
                principal = Some(basicHeader.username),
                errorMessage = None
              )
            case _ =>
              AuthenticationResult(
                success = false,
                None,
                Some("Invalid credentials")
              )
          }
          .recover {
            case _: Throwable =>
              AuthenticationResult(
                success = false,
                None,
                Some("A server error occurred")
              )
          }
      case None =>
        Future.successful(
          AuthenticationResult(
            success = false,
            principal = None,
            errorMessage = None
          )
        )
    }

  def challenge(context: AuthenticationContext): Map[String, String] =
    Map("WWW-Authenticate" -> s"""Basic realm="${config.realm}"""")

}
