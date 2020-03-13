package spinal.crypto.hash.sim


import spinal.core._
import spinal.core.sim._
import spinal.crypto._
import spinal.crypto.hash._

import scala.util.Random


object HashEngineIOsim {

  def initializeIO(dut: HashEngineIO): Unit ={
    dut.init      #= false
    dut.cmd.valid #= false
    dut.cmd.message.randomize()
  }


  def doSim(dut: HashEngineIO, clockDomain: ClockDomain, message: List[BigInt], refHash: BigInt): Unit = {


      dut.init #= true
      clockDomain.waitActiveEdge()
      dut.init #= false
      clockDomain.waitActiveEdge()

      var indexBlock = 0
      var rtlDigest = BigInt(0)

      while (indexBlock != message.length) {

        dut.cmd.valid #= true
        dut.cmd.message #= message(indexBlock)

        waitUntil(dut.rsp.valid.toBoolean == true)

        rtlDigest = dut.rsp.digest.toBigInt

        clockDomain.waitActiveEdge()

        dut.cmd.valid #= false

        clockDomain.waitActiveEdge()

        indexBlock += 1
      }

      assert(CastByteArray(rtlDigest.toByteArray, dut.rsp.digest.getWidth).sameElements(CastByteArray(refHash.toByteArray, dut.rsp.digest.getWidth)), s"RTL != REF ${BigIntToHexString(rtlDigest)} != ${BigIntToHexString(refHash)}")


  }
}

