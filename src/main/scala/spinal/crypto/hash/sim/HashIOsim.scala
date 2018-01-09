package spinal.crypto.hash.sim


import spinal.core._
import spinal.core.sim._
import spinal.crypto._
import spinal.crypto.hash.HashCoreIO

import scala.util.Random


object HashIOsim {

  def initializeIO(dut: HashCoreIO): Unit@suspendable ={
    dut.init      #= false
    dut.cmd.valid #= false
    dut.cmd.msg.randomize()
    dut.cmd.size.randomize()
    dut.cmd.last.randomize()
  }


  def doSim(dut: HashCoreIO, clockDomain: ClockDomain, lengthString: Int, msg: String = null)(refCrypto: (String) => Array[Byte]): Unit@suspendable = {

    val byteSizeMsg = dut.cmd.msg.getWidth / 8

    // init Hash
    clockDomain.waitActiveEdge()
    dut.init      #= true
    clockDomain.waitActiveEdge()
    dut.init      #= false
    clockDomain.waitActiveEdge()

    // Generate a random message + compute the reference hash
    var msgHex    = if(msg == null) List.fill(lengthString)(Random.nextPrintableChar()).mkString("") else msg
    val refDigest = refCrypto(msgHex)

    // number of iteration
    var index = math.ceil(msgHex.length  / byteSizeMsg.toDouble).toInt

    // Send all block of message
    while(index != 0) {

      val (msg, isLast) = if (msgHex.length > byteSizeMsg) (msgHex.substring(0, byteSizeMsg) -> false) else (msgHex + 0.toChar.toString * (byteSizeMsg - msgHex.length) -> true)

      dut.cmd.valid #= true
      dut.cmd.msg   #= BigInt(0x00.toByte +: (msg.map(_.toByte).reverse.toArray)) // Add 00 in front in order to get a positif number
      dut.cmd.size  #= BigInt(if (isLast) msgHex.length - 1 else 0)
      dut.cmd.last  #= isLast

      clockDomain.waitActiveEdge()

      // Wait the response
      if (isLast){
        waitUntil(dut.rsp.valid.toBoolean == true)

        val rtlDigest = CastByteArray(dut.rsp.digest.toBigInt.toByteArray, dut.cmd.msg.getWidth)

        assert(CastByteArray(refDigest, dut.cmd.msg.getWidth).sameElements(Endianness(rtlDigest)), s"REF != RTL ${BigIntToHexString(BigInt(refDigest))} != ${BigIntToHexString(BigInt(Endianness(rtlDigest)))}")

        clockDomain.waitActiveEdge()
      }else {
        waitUntil(dut.cmd.ready.toBoolean == true)
      }

      initializeIO(dut)

      clockDomain.waitActiveEdge()

      index -= 1
      msgHex = msgHex.drop(byteSizeMsg)
    }
  }
}

