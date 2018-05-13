package cryptotest

import org.scalatest.FunSuite
import ref.symmetric.TripleDES
import spinal.core._
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.symmetric.des.TripleDESCore_Std

import scala.util.Random



class SpinalSimTripleDESCoreTester extends FunSuite {


  /**
    * Test - TripleDESCore_Std
    */
  test("TripleDESCore_Std"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new TripleDESCore_Std()).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(20){

        SymmetricCryptoBlockIOSim.doSim(dut.io, dut.clockDomain, enc = Random.nextBoolean())(TripleDES.block(verbose = false))
      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }

}
