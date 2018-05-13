package cryptotest


import org.scalatest.FunSuite
import ref.hash.MD5
import spinal.crypto.hash.LITTLE_endian
import spinal.crypto.hash.md5.{MD5Core_Std, MD5Engine_Std}
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.{BigIntToHexString, CastByteArray}
import spinal.crypto.hash.sim.HashIOsim

import scala.util.Random


/**
  * Test MD5Core_Std
  */
class SpinalSimMD5CoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.compile(new MD5Core_Std())


  /**
    * Test 1
    */
  test("MD5CoreStd") {

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      var iteration = 100

      while(iteration != 0){

        HashIOsim.doSim(dut.io, dut.clockDomain, iteration, LITTLE_endian)(MD5.digest)

        iteration -=1
      }
    }
  }
}


/**
  * Test MD5Engine_Std
  */
class SpinalSimMD5EngineStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.compile(new MD5Engine_Std())


  /**
    * Test 1
    */
  test("MD5EngineStd") {

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init      #= false

      dut.clockDomain.waitActiveEdge()

      val refBlock = List(
        List(BigInt("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16)),
        List(BigInt("00000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16)),
        List(BigInt("80636261000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001800000000", 16)),
        List(BigInt("34333231383736353231303936353433303938373433323138373635323130393635343330393837343332313837363532313039363534333039383734333231", 16),
             BigInt("38373635323130393635343330393837000000800000000000000000000000000000000000000000000000000000000000000000000000000000028000000000", 16))
      )


      val refDigest = List(
        BigInt("031F1DAC6EA58ED01FAB67B774317791", 16),
        BigInt("D98C1DD404B2008F980980E97E42F8EC", 16),
        BigInt("98500190B04FD23C7D3F96D6727FE128", 16),
        BigInt("A2F4ED5755C9E32B2EDA49AC7AB60721", 16)
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
    }
  }
}
