package com.github.jarlah.authenticscala.digest

import org.scalatest.FlatSpec

class DigestHeaderParserTest extends FlatSpec {
  "null bascic header" should "return empty result" in {
    assert(DigestHeaderParser.extractDigestHeader("POST", null).isEmpty)
  }

  "proper digest header" should "return correct result" in {
    val header = DigestHeaderParser.extractDigestHeader(
      "POST",
      """Digest
        |   username="easycwmp",
        |   realm="freeacs",
        |   nonce="MTUzNDQ0NDIzNzc5NTpkM2RlYjZkN2FlYmRiNjE0MjFlMGVhZmM3NzliMTg2Mg==",
        |   uri="/tr069",
        |   algorithm="MD5",
        |   qop=auth,
        |   nc=00000001,
        |   cnonce="JYgUPfHn",
        |   response="a1ad4f95857ce5ea9f14bfb74624d4ed",
        |   opaque="f9d09cc4bd76ea6b36b0fb730e09b69f"""".stripMargin
    )
    assert(header.isDefined)
    assert(header.exists(_.userName == "easycwmp"))
    assert(header.exists(_.realm == "freeacs"))
    assert(
      header.exists(
        _.nonce == "MTUzNDQ0NDIzNzc5NTpkM2RlYjZkN2FlYmRiNjE0MjFlMGVhZmM3NzliMTg2Mg=="
      )
    )
    assert(header.exists(_.uri == "/tr069"))
    assert(header.exists(_.response == "a1ad4f95857ce5ea9f14bfb74624d4ed"))
    assert(header.exists(_.opaque == "f9d09cc4bd76ea6b36b0fb730e09b69f"))
    assert(header.exists(_.clientNonce == "JYgUPfHn"))
    assert(header.exists(_.qualityOfProtection == Auth))
    assert(header.exists(_.requestCounter == 1))
  }

  "Incorrect basic header" should "return empty result" in {
    assert(DigestHeaderParser.extractDigestHeader("POST", "Digest").isEmpty)
    assert(
      DigestHeaderParser.extractDigestHeader("POST", "Digest ").isEmpty
    )
    assert(
      DigestHeaderParser.extractDigestHeader("POST", "Digest ssdsdss").isEmpty
    )
  }
}
