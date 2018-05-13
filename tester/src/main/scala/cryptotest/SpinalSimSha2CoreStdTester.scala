package cryptotest



import org.scalatest.FunSuite
import ref.hash.SHA2
import spinal.core.SpinalConfig
import spinal.crypto.hash.BIG_endian
import spinal.crypto.hash.sim.{HashEngineIOsim, HashIOsim}

import spinal.sim._
import spinal.core.sim._
import spinal.crypto.hash.sha2._
import spinal.crypto._


import scala.util.Random


/**
  * Test SHA2Core_Std
  */
class SpinalSimSHA2CoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(2).compile(new SHA2Core_Std(SHA2_256))


  /**
    * Test 1
    */
  test("SHA2CoreStd_256") {

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      var iteration = 10

      while(iteration != 0){

        HashIOsim.doSim(dut.io, dut.clockDomain, iteration, BIG_endian )(SHA2.digest)

        iteration -= 1
      }
    }
  }
}


/**
  * Test Sha2Engine_Std
  */
class SpinalSimSHA2EngineStdTester extends FunSuite {


  /**
    * Test 1
    */
  test("SHA2Engine_Std_256") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(2).compile(new SHA2Engine_Std(SHA2_256))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val refBlock = List(
        List(BigInt("61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16)),
        List(BigInt("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000", 16),
          BigInt("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0", 16))
      )

      val refDigest = List(
        BigInt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 16),
        BigInt("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 16)
      )


      for((message, refHash) <- refBlock.zip(refDigest)){

        HashEngineIOsim.doSim(dut.io, dut.clockDomain, message, refHash)
      }

      dut.clockDomain.waitSampling(100)

      }
    }

    /**
      * Test 2
      */
    test("SHA2Engine_Std_512") {

      val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(2).compile(new SHA2Engine_Std(SHA2_512))

      compiledRTL.doSim { dut =>

        dut.clockDomain.forkStimulus(2)

        dut.io.cmd.valid #= false
        dut.io.cmd.message.randomize()
        dut.io.init #= false

        dut.clockDomain.waitActiveEdge()

        val refBlock = List(
          List(BigInt("6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16))

        )


        val refDigest = List(
          BigInt("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 16)
        )

        var index = 0

        while (index != refDigest.length) {

          dut.io.init #= true
          dut.clockDomain.waitActiveEdge()
          dut.io.init #= false
          dut.clockDomain.waitActiveEdge()

          var indexBlock = 0
          var rtlDigest = BigInt(0)

          while (indexBlock != refBlock(index).length) {

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

