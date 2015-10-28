package pdi.jwt

import argonaut._
import jawn.support.argonaut.Parser
import org.scalatest._

class ArgonautInstancesSpec extends FlatSpec with Matchers with JwtArgonautInstances {
  "DecodeJson[JwtHeader]" should "decode Json into JwtHeader" in {
    val header = JwtHeader(JwtAlgorithm.HS256)

    Parser.parseUnsafe(header.toJson).jdecode[JwtHeader] shouldBe DecodeResult.ok(header)
  }

  "DecodeJson[JwtClaim]" should "decode Json into JwtClaim" in {
    val claim = JwtClaim().by("me").to("you").about("something").issuedAt(10)
      .startsAt(10).expiresAt(15)

    Parser.parseUnsafe(claim.toJson).jdecode[JwtClaim] shouldBe DecodeResult.ok(claim)
  }
}
