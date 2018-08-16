package com.github.jarlah.authenticscala.digest

import com.github.jarlah.authenticscala.basic.{BasicHeader, BasicHeaderParser}
import org.scalatest.FlatSpec

class BasicHeaderParserTest extends FlatSpec {

  "null bascic header" should "return empty result" in {
    assert(BasicHeaderParser.extractBasicHeader(null).isEmpty)
  }

  "proper basic header" should "return correct result" in {
    val header =
      BasicHeaderParser.extractBasicHeader("Basic ZWFzeWN3bXA6ZWFzeWN3bXA=")
    assert(header.isDefined)
    assert(header.contains(BasicHeader("easycwmp", "easycwmp")))
  }

  "Incorrect basic header" should "return empty result" in {
    assert(BasicHeaderParser.extractBasicHeader("Basic").isEmpty)
    assert(BasicHeaderParser.extractBasicHeader("Basic ").isEmpty)
    assert(BasicHeaderParser.extractBasicHeader("Basic ssdsdss").isEmpty)
  }
}
