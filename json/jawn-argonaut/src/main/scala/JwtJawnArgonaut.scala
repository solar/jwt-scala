package pdi.jwt

import argonaut._
import argonaut.Json._
import jawn.support.argonaut.Parser
import monocle.function.Index

/**
 * Implementation of `JwtCore` using `Json` from argonaut.
 */
trait JwtJawnArgonaut extends JwtJsonCommon[Json] with JwtArgonautInstances {
  protected def parse(value: String): Json = Parser.parseUnsafe(value)

  protected def stringify(value: Json): String = value.nospaces

  protected def getAlgorithm(header: Json): Option[JwtAlgorithm] = {
    jObjectPrism.composeOptional(Index.index("alg")).getOption(header).flatMap { j =>
      algoDecodeJson.decode(j.hcursor).toOption
    }.flatten
  }

  protected def parseHeader(header: String): JwtHeader = {
    Parser.parseFromString(header).toOption.map { json =>
      val result = json.jdecode[JwtHeader]
      result.value.getOrElse(throw new RuntimeException(
        s"Failed to decode header json: ${result.message.getOrElse("")}"))
    }.getOrElse(throw new RuntimeException("Failed to parse a jwt header"))
  }

  protected def parseClaim(claim: String): JwtClaim = {
    Parser.parseFromString(claim).toOption.map { json =>
      val result = json.jdecode[JwtClaim]
      result.value.getOrElse(throw new RuntimeException(
        s"Failed to decode claim json: ${result.message.getOrElse("")}"))
    }.getOrElse(throw new RuntimeException("Failed to parse a jwt claim"))
  }
}

object JwtJawnArgonaut extends JwtJawnArgonaut
