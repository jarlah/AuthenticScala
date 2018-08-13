package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.{
  AuthenticationContext,
  AuthenticationResult,
  Authenticator
}

final case class DigestAuthenticator(config: DigestAuthenticatorConfiguration)
    extends Authenticator[DigestAuthenticatorConfiguration] {

  val privateHashEncoder: PrivateHashEncoder = PrivateHashEncoder(
    config.privateKey
  )

  def authenticate(context: AuthenticationContext): AuthenticationResult = {
    if (null == context) {
      throw new IllegalArgumentException("missing context")
    }
    val authHeader = context.httpHeaders.getOrElse("Authorization", "")
    DigestAuthHeaderParser
      .extractDigestHeader(context.httpMethod, authHeader) match {
      case Right(digestHeader) =>
        AuthenticationResult(
          success = true,
          principal = Some(digestHeader.userName),
          errorMessage = None
        )
      case Left(error) =>
        AuthenticationResult(
          success = false,
          principal = None,
          errorMessage = Some(error)
        )
    }
  }
}

object DigestAuthenticator {}
