package cryptotest


import org.scalatest.FunSuite
import ref.hash.SHA3
import spinal.core._
import spinal.crypto.hash.BIG_endian
import spinal.crypto.hash.sim.HashIOsim
import spinal.sim._
import spinal.core.sim._
import spinal.crypto._
import spinal.crypto.hash.sha3.{SHA3_512, Sha3Core_Std}



/**
  * Test SHA3Core_Std
  */
class SpinalSimSha3CoreStdTester extends FunSuite {


  /**
    *  SHA3CoreStd_512
    */
  test("SHA3CoreStd_512") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new Sha3Core_Std(SHA3_512))

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      var iteration = 100

      while(iteration != 0){

        HashIOsim.doSim(dut.io, dut.clockDomain, iteration, BIG_endian)(SHA3.digest(512))

        iteration -= 1
      }

      dut.clockDomain.waitActiveEdge(5)
    }
  }
}

