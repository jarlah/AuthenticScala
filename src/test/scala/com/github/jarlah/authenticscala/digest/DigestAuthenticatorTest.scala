package com.github.jarlah.authenticscala.digest

import java.util.concurrent.TimeUnit

import com.github.jarlah.authenticscala.Authenticator.PasswordRetriever
import com.github.jarlah.authenticscala.{AuthenticationContext, Authenticator}
import org.scalatest.FlatSpec

import scala.concurrent.{Await, Future}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration

class DigestAuthenticatorTest extends FlatSpec {
  val retriever: PasswordRetriever = (u: String) => Future.successful(u)

  val timeout = FiniteDuration(1, TimeUnit.SECONDS)

  "An invalid digest header" should "return failed authentication result" in {
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> "Invalid...."),
      "127.0.0.1"
    )
    val result = Await.result(
      Authenticator.authenticate(context, retriever, "digest"),
      timeout
    )
    assert(!result.success)
    assert(result.errorMessage.isEmpty)
  }

  "A digest header with auth-int in qop" should "return failed authentication result" in {
    val digestheader =
      """Digest
        |realm="testrealm@host.com",
        |qop="auth, auth-int",
        |nonce="MTUzNDM1NzI0MjAwMTo1M2RiMjEyZWIyMDY3NjI0MGQ2NzJmMWZmMjM4Nzc1Yg==",
        |opaque="5ccc069c403ebaf9f0171e9517f40e41
        |"""".stripMargin
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> digestheader),
      "127.0.0.1"
    )
    val result = Await.result(
      Authenticator.authenticate(context, retriever, "digest"),
      timeout
    )
    assert(!result.success)
    assert(result.errorMessage.contains("Invalid credentials"))
  }

  "challenge" should "create none empty map" in {
    val context = AuthenticationContext(
      "POST",
      "/",
      Map(),
      "127.0.0.1"
    )
    assert(Authenticator.challenge(context, "digest").nonEmpty)
  }
}
