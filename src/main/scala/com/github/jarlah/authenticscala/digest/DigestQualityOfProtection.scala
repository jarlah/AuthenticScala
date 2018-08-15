package com.github.jarlah.authenticscala.digest

sealed abstract class DigestQualityOfProtection(val name: String)
case object Auth              extends DigestQualityOfProtection("auth")
case object AuthWithIntegrity extends DigestQualityOfProtection("auth-int")
