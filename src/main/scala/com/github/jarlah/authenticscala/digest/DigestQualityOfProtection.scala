package com.github.jarlah.authenticscala.digest

sealed trait DigestQualityOfProtection {
  val name: String
}

case object Authentication extends DigestQualityOfProtection {
  val name = "auth"
}
case object AuthenticationWithIntegrity extends DigestQualityOfProtection {
  val name = "auth-int"
}
