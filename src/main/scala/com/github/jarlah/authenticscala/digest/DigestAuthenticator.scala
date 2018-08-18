package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}
import com.typesafe.config.ConfigFactory
import scala.concurrent.{ExecutionContext, Future}
import DigestHeaderParser._
import NonceManager._
import OpaqueManager._

object DigestAuthenticator {
  val config = DigestConfiguration(ConfigFactory.load)

  def apply(): DigestAuthenticator =
    DigestAuthenticator(config)

  def challenge(context: AuthenticationContext): Map[String, String] =
    DigestAuthenticator().challenge(context)
}

final case class DigestAuthenticator(config: DigestConfiguration)
    extends Authenticator[DigestConfiguration] {

  def authenticate(
      context: AuthenticationContext,
      retriever: PasswordRetriever
  )(implicit ec: ExecutionContext): Future[AuthenticationResult] =
    getHeader(context).map { header =>
      retriever(header.userName).map {
        case Some(userPassword) =>
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
              errorMessage = Some("Invalid credentials")
            )
          }
        case _ =>
          AuthenticationResult(
            success = false,
            principal = None,
            errorMessage = None
          )
      }.recover {
        case _: Throwable =>
          AuthenticationResult(
            success = false,
            principal = None,
            errorMessage = Some("A server error occurred")
          )
      }
    }.getOrElse(
      Future.successful(
        AuthenticationResult(
          success = false,
          principal = None,
          errorMessage = None
        )
      )
    )

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
        s"""Digest realm="${config.realm}", nonce="$nonce", opaque="$opaque", stale=$isStale, algorithm=MD5, qop="${Auth.name}""""
    )
  }

  private[this] def getHeader(context: AuthenticationContext) =
    extractDigestHeader(context.httpMethod, context.getAuthHeader)
}
