package cryptotest


import org.scalatest.funsuite.AnyFunSuite
import ref.hash.MD5

import spinal.core._
import spinal.core.sim._

import spinal.crypto.hash.LITTLE_endian
import spinal.crypto.hash.md5.{MD5Core_Std, MD5Engine_Std}
import spinal.crypto.hash.sim.{HashEngineIOsim, HashIOsim}




/**
  * Test MD5Core_Std
  */
class SpinalSimMD5CoreStdTester extends AnyFunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new MD5Core_Std())

  val NBR_ITERATION = 100

  /**
    * Test 1
    */
  test("MD5CoreStd") {

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, LITTLE_endian)(MD5.digest)
      }
    }
  }
}


/**
  * Test MD5Engine_Std
  */
class SpinalSimMD5EngineStdTester extends AnyFunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new MD5Engine_Std())


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

      val messages = List(
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

      for((ref, msg) <- refDigest.zip(messages)){
        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)
      }
    }
  }
}
