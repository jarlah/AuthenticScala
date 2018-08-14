package com.github.jarlah.authenticscala

case class AuthenticationResult(
    success: Boolean,
    principal: Option[String],
    errorMessage: Option[String]
)
