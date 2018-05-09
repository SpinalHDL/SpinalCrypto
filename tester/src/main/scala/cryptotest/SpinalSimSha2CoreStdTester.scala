package cryptotest



import org.scalatest.FunSuite

import spinal.sim._
import spinal.core.sim._
import spinal.crypto.hash.sha2.Sha2Engine_Std
import spinal.crypto._


import scala.util.Random



/**
  * Test Sha2Engine_Std
  */
class SpinalSimSha2CoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withWave(2).compile(new Sha2Engine_Std())


  /**
    * Test 1
    */
  test("Sha2Engine_Std") {

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init      #= false

      dut.clockDomain.waitActiveEdge()

      val refBlock = List(
        List(BigInt("61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16))
      )


      val refDigest = List(
        BigInt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 16)
      )

      var index = 0

      while(index != refDigest.length ){

        dut.io.init #= true
        dut.clockDomain.waitActiveEdge()
        dut.io.init #= false
        dut.clockDomain.waitActiveEdge()

        var indexBlock = 0
        var rtlDigest = BigInt(0)

        while(indexBlock != refBlock(index).length ){

          dut.io.cmd.valid #= true
          dut.io.cmd.message #= refBlock(index)(indexBlock)

          waitUntil(dut.io.rsp.valid.toBoolean == true)

          rtlDigest = dut.io.rsp.digest.toBigInt

          dut.clockDomain.waitActiveEdge()

          dut.io.cmd.valid #= false

          dut.clockDomain.waitActiveEdge()

          indexBlock += 1
        }

        assert(CastByteArray(rtlDigest.toByteArray, dut.io.rsp.digest.getWidth).sameElements(CastByteArray(refDigest(index).toByteArray, dut.io.rsp.digest.getWidth)), s"RTL != REF ${BigIntToHexString(rtlDigest)} != ${BigIntToHexString(refDigest(index))}")

        index += 1
      }

      dut.clockDomain.waitSampling(100)

    }
  }
}

