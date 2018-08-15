package com.github.jarlah.authenticscala.digest

import java.util.concurrent.TimeUnit

import com.github.jarlah.authenticscala.AuthenticationContext
import com.typesafe.config.{Config, ConfigFactory}
import org.scalatest.FlatSpec

import scala.concurrent.{Await, Future}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration

class DigestAuthenticatorTest extends FlatSpec {
  val authenticator = DigestAuthenticator()

  val passwordRetriever = (u: String) => Future.successful(u)

  val timeout = FiniteDuration(1, TimeUnit.SECONDS)

  "An invalid digest header" should "return failed authentication result" in {
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> "Invalid...."),
      "127.0.0.1"
    )
    val result = Await.result(
      authenticator.authenticate(context, u => Future.successful(u)),
      timeout
    )
    assert(!result.success)
    assert(
      result.errorMessage.contains(
        "AuthHeader cannot be null or empty OR does not start with Digest"
      )
    )
  }

  "A digest header with auth-int in qop" should "return failed authentication result" in {
    val digestheader =
      """Digest
        |realm="testrealm@host.com",
        |qop="auth, auth-int",
        |nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        |opaque="5ccc069c403ebaf9f0171e9517f40e41
        |"""".stripMargin
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> digestheader),
      "127.0.0.1"
    )
    val result = Await.result(
      authenticator.authenticate(context, passwordRetriever),
      timeout
    )
    assert(!result.success)
    assert(result.errorMessage.contains("auth-int is not currently supported"))
  }

  "challenge" should "create none empty map" in {
    val context = AuthenticationContext(
      "POST",
      "/",
      Map(),
      "127.0.0.1"
    )
    assert(authenticator.challenge(context).nonEmpty)
  }
}
