package pdi.jwt

import argonaut._
import pdi.jwt.exceptions.JwtNonSupportedAlgorithm

trait JwtArgonautInstances {
  implicit val headerDecodeJson: DecodeJson[JwtHeader] = DecodeJson { c =>
    for {
      typ <- strDecodeJson.tryDecode(c --\ "typ")
      alg <- algoDecodeJson.tryDecode(c --\ "alg")
      cty <- strDecodeJson.tryDecode(c --\ "cty")
    } yield JwtHeader(alg, typ, cty)
  }

  implicit val claimDecodeJson: DecodeJson[JwtClaim] = DecodeJson { c =>
    for {
      iss <- strDecodeJson.tryDecode(c --\ "iss")
      sub <- strDecodeJson.tryDecode(c --\ "sub")
      aud <- strDecodeJson.tryDecode(c --\ "aud")
      exp <- longDecodeJson.tryDecode(c --\ "exp")
      nbf <- longDecodeJson.tryDecode(c --\ "nbf")
      iat <- longDecodeJson.tryDecode(c --\ "iat")
      jwtId <- strDecodeJson.tryDecode(c --\ "jti")
      content <- DecodeResult.ok(filterClaim(c.focus))
    } yield JwtClaim(content.nospaces, iss, sub, aud, exp, nbf, iat, jwtId)
  }

  implicit val algoDecodeJson: DecodeJson[Option[JwtAlgorithm]] = hcursor { c =>
    c.focus.string match {
      case Some("none") => DecodeResult.ok(None)
      case Some(alg) => {
        try {
          DecodeResult.ok(JwtAlgorithm.optionFromString(alg))
        } catch {
          case e: JwtNonSupportedAlgorithm =>
            DecodeResult.fail(s"$alg is not supported", c.history)
        }
      }
      case _ => {
        if (c.focus.isNull) DecodeResult.ok(None)
        else DecodeResult.fail("Expects string for JWT header (alg)", c.history)
      }
    }
  }

  private[this] def hcursor[A]: (HCursor => DecodeResult[Option[A]]) => DecodeJson[Option[A]] = f => DecodeJson.withReattempt { a =>
    a.success match {
      case None => DecodeResult.ok(None)
      case Some(c) => f(c)
    }
  }

  private[this] val strDecodeJson: DecodeJson[Option[String]] = hcursor { c =>
    c.focus.string match {
      case Some(s) => DecodeResult.ok(Some(s))
      case _ => {
        if (c.focus.isNull) DecodeResult.ok(None)
        else DecodeResult.fail("Expected a string", c.history)
      }
    }
  }

  private[this] val longDecodeJson: DecodeJson[Option[Long]] = hcursor { c =>
    c.focus.number match {
      case Some(n) => DecodeResult.ok(Some(n.truncateToLong))
      case _ => {
        if (c.focus.isNull) DecodeResult.ok(None)
        else DecodeResult.fail("Expected a number", c.history)
      }
    }
  }

  private[this] val filterClaim: Json => Json = json => Json.jObjectAssocList(
    json.objectOrEmpty.toMap.filterKeys {
      case "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti" => false
      case _ => true
    }.toList)
}

object argonautImplicits extends JwtArgonautInstances
