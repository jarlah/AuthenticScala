package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.AuthenticationContext
import org.scalatest.FlatSpec

import scala.concurrent.Future

class DigestAuthenticatorTest extends FlatSpec {

  "An invalid digest header" should "return failed authentication result" in {
    val authenticator =
      DigestAuthenticator(DigestAuthenticatorConfiguration(Future.successful))
    val result = authenticator.authenticate(
      AuthenticationContext("POST", "/", Map("Authorization" -> "Invalid..."))
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
    val authenticator =
      DigestAuthenticator(DigestAuthenticatorConfiguration(Future.successful))
    val result = authenticator.authenticate(
      AuthenticationContext("POST", "/", Map("Authorization" -> digestheader))
    )
    assert(!result.success)
    assert(result.errorMessage.contains("auth-int is not currently supported"))
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
      DigestAuthenticator(DigestAuthenticatorConfiguration(Future.successful))
    val result = authenticator.authenticate(
      AuthenticationContext("POST", "/", Map("Authorization" -> digestheader))
    )
    assert(result.success)
    assert(result.errorMessage.isEmpty)
  }
}
