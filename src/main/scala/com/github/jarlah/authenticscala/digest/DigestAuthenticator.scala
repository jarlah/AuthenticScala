package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}

import scala.concurrent.{ExecutionContext, Future}

final case class DigestAuthenticator(config: DigestAuthenticatorConfiguration)
    extends Authenticator[DigestAuthenticatorConfiguration] {

  val privateHashEncoder: PrivateHashEncoder = PrivateHashEncoder(
    config.privateKey
  )

  def authenticate(
      context: AuthenticationContext
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] = {
    if (null == context) {
      throw new IllegalArgumentException("missing context")
    }
    val authHeader = context.httpHeaders.getOrElse("Authorization", "")
    DigestAuthHeaderParser
      .extractDigestHeader(context.httpMethod, authHeader) match {
      case Right(digestHeader) =>
        config
          .passwordRetriever(digestHeader.userName)
          .map(
            secret =>
              AuthenticationResult(
                success = secret.equals(digestHeader.userName),
                principal = Some(digestHeader.userName),
                errorMessage = None
            )
          )
          .recover {
            case e: Throwable =>
              AuthenticationResult(
                success = false,
                principal = None,
                errorMessage = Some(e.getLocalizedMessage)
              )
          }

      case Left(error) =>
        Future.successful(
          AuthenticationResult(
            success = false,
            principal = None,
            errorMessage = Some(error)
          )
        )
    }
  }
}

object DigestAuthenticator {}
