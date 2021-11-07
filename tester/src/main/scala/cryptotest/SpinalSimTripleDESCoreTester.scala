package cryptotest

import org.scalatest.funsuite.AnyFunSuite
import ref.symmetric.TripleDES
import spinal.core._
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.core.sim._
import spinal.crypto.symmetric.des.TripleDESCore_Std

import scala.util.Random



class SpinalSimTripleDESCoreTester extends AnyFunSuite {


  /**
    * Test - TripleDESCore_Std
    */
  test("TripleDESCore_Std"){

    val NBR_ITERATION = 20

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new TripleDESCore_Std()).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for(_ <- 0 to NBR_ITERATION){
        SymmetricCryptoBlockIOSim.doSim(dut.io, dut.clockDomain, enc = Random.nextBoolean())(TripleDES.block(verbose = false))
      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }

}
