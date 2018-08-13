package com.github.jarlah.authenticscala.digest

import java.util.concurrent.TimeUnit

import com.github.jarlah.authenticscala.AuthenticationContext
import org.scalatest.FlatSpec

import scala.concurrent.{Await, Future}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration

class DigestAuthenticatorTest extends FlatSpec {

  "An invalid digest header" should "return failed authentication result" in {
    val authenticator =
      DigestAuthenticator(
        DigestAuthenticatorConfiguration(
          Future.successful
        )
      )
    val r = Await.result(
      authenticator.authenticate(
        AuthenticationContext(
          "POST",
          "/",
          Map("Authorization" -> "Invalid...."),
          "127.0.0.1"
        )
      ),
      FiniteDuration(1, TimeUnit.SECONDS)
    )
    assert(!r.success)
    assert(
      r.errorMessage.contains(
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
    val authenticator =
      DigestAuthenticator(
        DigestAuthenticatorConfiguration(
          Future.successful
        )
      )
    val r = Await.result(
      authenticator.authenticate(
        AuthenticationContext(
          "POST",
          "/",
          Map("Authorization" -> digestheader),
          "127.0.0.1"
        )
      ),
      FiniteDuration(1, TimeUnit.SECONDS)
    )
    assert(!r.success)
    assert(r.errorMessage.contains("auth-int is not currently supported"))
  }

  "A valid digest header" should "return successfully authentication result" in {
    val digestheader =
      """Digest username="Mufasa",
        |realm="testrealm@host.com",
        |nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        |uri="/dir/index.html",
        |qop=auth,
        |nc=00000001,
        |cnonce="0a4f113b",
        |response="6629fae49393a05397450978507c4ef1",
        |opaque="5ccc069c403ebaf9f0171e9517f40e41"
      """.stripMargin
    val authenticator =
      DigestAuthenticator(
        DigestAuthenticatorConfiguration(
          Future.successful
        )
      )
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> digestheader),
      "127.0.0.1"
    )
    val r = Await.result(
      authenticator.authenticate(context),
      FiniteDuration(1, TimeUnit.SECONDS)
    )
    assert(r.success)
    assert(r.errorMessage.isEmpty)
  }

  "dsd" should "dadd" in {
    val authenticator =
      DigestAuthenticator(
        DigestAuthenticatorConfiguration(
          Future.successful
        )
      )
    val context = AuthenticationContext(
      "POST",
      "/",
      Map(),
      "127.0.0.1"
    )
    println(authenticator.challenge(context))
  }
}
