package pdi.jwt

import argonaut.Json

class JwtJawnArgonautSpec extends JwtJsonCommonSpec[Json] with JsonFixture {
  val jwtJsonCommon = JwtJawnArgonaut
}
