package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}

import scala.concurrent.{ExecutionContext, Future}

object DigestAuthenticator {
  def apply(passwordRetriever: PasswordRetriever): DigestAuthenticator =
    DigestAuthenticator(DigestAuthenticatorConfiguration(passwordRetriever))

  def challenge(context: AuthenticationContext): Map[String, String] =
    new DigestAuthenticator(DigestAuthenticatorConfiguration(Future.successful))
      .challenge(context)
}

final case class DigestAuthenticator(config: DigestAuthenticatorConfiguration)
    extends Authenticator[DigestAuthenticatorConfiguration] {

  private val privateHashEncoder = PrivateHashEncoder(config.noncePrivateKey)

  def authenticate(
      context: AuthenticationContext
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] = {
    val authHeader = context.httpHeaders.getOrElse("Authorization", "")
    DigestAuthHeaderParser
      .extractDigestHeader(context.httpMethod, authHeader) match {
      case Right(digestHeader) =>
        config
          .passwordRetriever(digestHeader.userName)
          .map(
            userPassword => {
              if (NonceManager.validate( // nonce is valid
                    digestHeader.nonce,
                    context.remoteAddress,
                    privateHashEncoder
                  ) && !NonceManager.stale( // nonce is not stale
                    digestHeader.nonce,
                    config.nonceValidInMillis
                  ) && digestHeader.matchesCredentials( // credentials match
                    config.realm,
                    OpaqueManager.generate(digestHeader.nonce),
                    userPassword
                  )) {
                AuthenticationResult(
                  success = true,
                  principal = Some(digestHeader.userName),
                  errorMessage = None
                )
              } else {
                AuthenticationResult(
                  success = false,
                  principal = None,
                  errorMessage = None
                )
              }
            }
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

  def challenge(context: AuthenticationContext): Map[String, String] = {
    val authHeader = context.httpHeaders.getOrElse("Authorization", "")
    val stale = DigestAuthHeaderParser
      .extractDigestHeader(context.httpMethod, authHeader) match {
      case Right(digestHeader) =>
        NonceManager.validate(
          digestHeader.nonce,
          context.remoteAddress,
          privateHashEncoder
        ) && NonceManager.stale(
          digestHeader.nonce,
          config.nonceValidInMillis
        )
      case _ =>
        false
    }
    val nonce  = NonceManager.generate(context.remoteAddress, privateHashEncoder)
    val opaque = OpaqueManager.generate(nonce)
    Map(
      "WWW-Authenticate" ->
        s"""Digest realm="${config.realm}", nonce="$nonce", opaque="$opaque", stale=$stale, algorithm=MD5, qop="auth""""
    )
  }
}
