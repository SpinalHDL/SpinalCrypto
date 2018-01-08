package spinal.crypto.hash.sim


import spinal.core._
import spinal.core.sim._
import spinal.crypto.hash.HashCoreIO

import scala.util.Random




object HashIOsim {

  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  def endianess(input: Array[Byte]): Array[Byte] = {
    assert(input.length % 4 == 0)

    return input.grouped(4).flatMap(_.reverse.toList).toArray
  }

  def castByteArray(input: Array[Byte], castSize: Int): Array[Byte] = {
    if(input.length == castSize){
      input
    }else if(input.length > castSize){
      input.takeRight(castSize)
    }else{
      Array.fill[Byte](castSize - input.length)(0x00) ++ input
    }
  }

  def initializeIO(dut: HashCoreIO): Unit@suspendable ={
    dut.init #= false
    dut.cmd.valid #= false
    dut.cmd.msg.randomize()
    dut.cmd.size.randomize()
    dut.cmd.last.randomize()
  }

  def doSim(dut: HashCoreIO, clockDomain: ClockDomain, lengthString: Int, msg: String = null)(refCrypto: (String) => Array[Byte]): Unit@suspendable = {

    // init Hash
    clockDomain.waitActiveEdge()
    dut.init      #= true
    clockDomain.waitActiveEdge()
    dut.init      #= false
    clockDomain.waitActiveEdge()

    // Generate a random message + compute the reference hash
    var msgHex    = if(msg == null) List.fill(lengthString)(Random.nextPrintableChar()).mkString("") else msg
    val refDigest = refCrypto(msgHex)

    var index = math.ceil(msgHex.length  / 4.0).toInt


    while(index != 0) {

      val (msg, isLast) = if (msgHex.length > 4) (msgHex.substring(0, 4) -> false) else (msgHex + 0.toChar.toString * (4 - msgHex.length) -> true)

      dut.cmd.valid #= true
      dut.cmd.msg   #= BigInt(0x00.toByte +: (msg.map(_.toByte).reverse.toArray)) // Add 00 in front in order to get a positif number
      dut.cmd.size  #= BigInt(if (isLast) msgHex.length - 1 else 0)
      dut.cmd.last  #= isLast

      clockDomain.waitActiveEdge()

      // Wait the response
      if (isLast){
        waitUntil(dut.rsp.valid.toBoolean == true)

        val rtlDigest = castByteArray(dut.rsp.digest.toBigInt.toByteArray, 32)

        assert(castByteArray(refDigest, 32).sameElements(endianess(rtlDigest)), s"REF != RTL ${bigIntToHex(BigInt(refDigest))} != ${bigIntToHex(BigInt(endianess(rtlDigest)))}")

        clockDomain.waitActiveEdge()
      }else {
        waitUntil(dut.cmd.ready.toBoolean == true)
      }

      dut.cmd.valid #= false

      clockDomain.waitActiveEdge()

      index -= 1
      msgHex = msgHex.drop(4)
    }
  }
}

