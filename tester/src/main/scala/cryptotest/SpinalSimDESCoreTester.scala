package cryptotest

import org.scalatest.FunSuite
import ref.symmetric.DES

import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim

import spinal.sim._
import spinal.core.sim._
import spinal.crypto.symmetric.des.DESCore_Std

import scala.util.Random



class SpinalSimDESCoreTester extends FunSuite {


  /**
    * Test - DESCore_STD
    */
  test("DESCore_Std"){

    SimConfig.compile(new DESCore_Std()).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(20){

        SymmetricCryptoBlockIOSim.doSim(dut.io, dut.clockDomain, enc = Random.nextBoolean())(DES.block(verbose = false))
      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }
}
