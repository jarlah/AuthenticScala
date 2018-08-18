package com.github.jarlah.authenticscala.digest

import java.util.concurrent.TimeUnit

import com.github.jarlah.authenticscala.{AuthenticationContext, Authenticator}
import org.scalatest.FlatSpec

import scala.concurrent.{Await, Future}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration

class BasicAuthenticatorTest extends FlatSpec {

  val timeout = FiniteDuration(1, TimeUnit.SECONDS)

  "proper header" should "result in success" in {
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> "Basic ZWFzeWN3bXA6ZWFzeWN3bXA="),
      "127.0.0.1"
    )
    val result = Await.result(
      Authenticator.authenticate(
        context,
        (u: String) => Future.successful(Some(u)),
        "basic"
      ),
      timeout
    )
    assert(result.success)
    assert(result.errorMessage.isEmpty)
  }

  "wrong password" should "result in error" in {
    val context = AuthenticationContext(
      "POST",
      "/",
      Map("Authorization" -> "Basic ZWFzeWN3bXA6ZWFzeWN3bXA="),
      "127.0.0.1"
    )
    val result = Await.result(
      Authenticator.authenticate(
        context,
        (u: String) => Future.successful(Some("wrong")),
        "basic"
      ),
      timeout
    )
    assert(!result.success)
    assert(result.errorMessage.contains("Invalid credentials"))
  }
}
