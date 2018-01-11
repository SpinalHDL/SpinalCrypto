package cryptotest

import org.scalatest.FunSuite
import ref.symmetric.DES

import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim

import spinal.sim._
import spinal.core.sim._
import spinal.crypto.symmetric.des.DESCore_Std

import scala.util.Random



class SpinalSimDESCoreStdTester extends FunSuite {


  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  // RTL to simulate
  val compiledRTL = SimConfig.compile(new DESCore_Std())


  /**
    * Test 1
    */
  test("DESCoreStd_notReleaseValid"){

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        SymmetricCryptoBlockIOSim.simWithValidNotRelease(dut.io, dut.clockDomain, enc = true )(DES.block(verbose = false))
        SymmetricCryptoBlockIOSim.simWithValidNotRelease(dut.io, dut.clockDomain, enc = false)(DES.block(verbose = false))

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }


  /**
    * Test 2
    */
  test("DESCoreStd_releaseValid"){

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        SymmetricCryptoBlockIOSim.simWithValidReleased(dut.io, dut.clockDomain, enc = true )(DES.block(verbose = false))
        SymmetricCryptoBlockIOSim.simWithValidReleased(dut.io, dut.clockDomain, enc = false)(DES.block(verbose = false))

      }
    }
  }
}
