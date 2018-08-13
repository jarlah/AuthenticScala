package com.github.jarlah.authenticscala.digest

sealed trait DigestQualityOfProtection

case object Authentication              extends DigestQualityOfProtection
case object AuthenticationWithIntegrity extends DigestQualityOfProtection
