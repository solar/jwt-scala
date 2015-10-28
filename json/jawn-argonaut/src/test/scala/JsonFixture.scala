package pdi.jwt

import argonaut.Json
import jawn.support.argonaut.Parser

case class JsonDataEntry (
  algo: JwtAlgorithm,
  header: String,
  headerClass: JwtHeader,
  header64: String,
  signature: String,
  token: String,
  tokenUnsigned: String,
  tokenEmpty: String,
  headerJson: Json) extends JsonDataEntryTrait[Json]

trait JsonFixture extends JsonCommonFixture[Json] {
  val claimJson = Parser.parseUnsafe(claimClass.toJson)
  val headerEmptyJson = Parser.parseUnsafe(headerClassEmpty.toJson)

  def mapData(data: DataEntryBase): JsonDataEntry = JsonDataEntry(
    algo = data.algo,
    header = data.header,
    headerClass = data.headerClass,
    header64 = data.header64,
    signature = data.signature,
    token = data.token,
    tokenUnsigned = data.tokenUnsigned,
    tokenEmpty = data.tokenEmpty,
    headerJson = Parser.parseUnsafe(data.headerClass.toJson)
  )
}
