package com.github.jarlah.authenticscala

final case class AuthenticationResult(
    success: Boolean,
    principal: Option[String],
    errorMessage: Option[String]
)
