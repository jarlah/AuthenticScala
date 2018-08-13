package com.github.jarlah.authenticscala

case class AuthenticationContext(
    httpMethod: String,
    httpUri: String,
    httpHeaders: Map[String, String],
    remoteAddress: String
)
