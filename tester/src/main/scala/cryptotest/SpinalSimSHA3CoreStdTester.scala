package cryptotest


import org.scalatest.funsuite.AnyFunSuite
import ref.hash.SHA3
import spinal.core._
import spinal.crypto.hash.BIG_endian
import spinal.crypto.hash.sim.HashIOsim
import spinal.core.sim._
import spinal.crypto.hash.sha3._



/**
  * Test SHA3Core_Std
  *
  * Pattern : https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
  *
  */
class SpinalSimSHA3CoreStdTester extends AnyFunSuite {

  val NBR_ITERATION = 100

  /**
    *  SHA3CoreStd_512
    */
  test("SHA3CoreStd_512") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA3Core_Std(SHA3_512))

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, BIG_endian)(SHA3.digest(512))
      }

      dut.clockDomain.waitActiveEdge(5)
    }
  }

  /**
    *  SHA3CoreStd_384
    */
  test("SHA3CoreStd_384") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA3Core_Std(SHA3_384))

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()


      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, BIG_endian)(SHA3.digest(384))
      }

      dut.clockDomain.waitActiveEdge(5)
    }
  }

  /**
    *  SHA3CoreStd_256
    */
  test("SHA3CoreStd_256") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA3Core_Std(SHA3_256))

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()


      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, BIG_endian)(SHA3.digest(256))
      }

      dut.clockDomain.waitActiveEdge(5)
    }
  }

  /**
    *  SHA3CoreStd_224
    */
  test("SHA3CoreStd_224") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA3Core_Std(SHA3_224))

    compiledRTL.doSim{ dut =>


      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()


      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, BIG_endian)(SHA3.digest(224))
      }

      dut.clockDomain.waitActiveEdge(5)
    }
  }
}

