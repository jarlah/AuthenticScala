package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}
import com.typesafe.config.ConfigFactory
import scala.concurrent.{ExecutionContext, Future}
import DigestAuthHeaderParser._
import NonceManager._
import OpaqueManager._

object DigestAuthenticator {
  val config = DigestAuthenticatorConfiguration(ConfigFactory.load)

  def apply(): DigestAuthenticator =
    DigestAuthenticator(config)

  def challenge(context: AuthenticationContext): Map[String, String] =
    DigestAuthenticator().challenge(context)
}

final case class DigestAuthenticator(config: DigestAuthenticatorConfiguration)
    extends Authenticator[DigestAuthenticatorConfiguration] {

  def authenticate(
      context: AuthenticationContext,
      retriever: PasswordRetriever
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] = {
    getHeader(context) match {
      case Some(header) =>
        retriever(header.userName)
          .map(
            userPassword => {
              if (validate( // nonce is valid
                    header.nonce,
                    context.remoteAddress,
                    config.encoder
                  ) && !stale( // nonce is not stale
                    header.nonce,
                    config.nonceTimeout
                  ) && header.matchesCredentials( // credentials match
                    config.realm,
                    getOpaque(header.nonce),
                    userPassword
                  )) {
                AuthenticationResult(
                  success = true,
                  principal = Some(header.userName),
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
      case None =>
        Future.successful(
          AuthenticationResult(
            success = false,
            principal = None,
            errorMessage = None
          )
        )
    }

  }

  def challenge(context: AuthenticationContext): Map[String, String] = {
    val isStale = getHeader(context).exists(
      header =>
        validate(
          header.nonce,
          context.remoteAddress,
          config.encoder
        ) && stale(
          header.nonce,
          config.nonceTimeout
      )
    )
    val nonce  = generate(context.remoteAddress, config.encoder)
    val opaque = getOpaque(nonce)
    Map(
      "WWW-Authenticate" ->
        s"""Digest realm="${config.realm}", nonce="$nonce", opaque="$opaque", stale=$isStale, algorithm=MD5, qop="auth""""
    )
  }

  private[this] def getHeader(context: AuthenticationContext) =
    extractDigestHeader(context.httpMethod, context.getAuthHeader)
}
