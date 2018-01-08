package cryptotest


import org.scalatest.FunSuite
import ref.hash.MD5

import spinal.crypto.hash.md5.MD5Core_Std
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.hash.sim.HashIOsim

import scala.util.Random



class SpinalSimMD5CoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withWave(2).compile(new MD5Core_Std())


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

        HashIOsim.doSim(dut.io, dut.clockDomain, iteration)(MD5.digest)

        iteration -=1
      }
    }
  }
}