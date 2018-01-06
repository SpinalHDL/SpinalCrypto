package cryptotest

import org.scalatest.FunSuite
import ref.assymetric.TripleDES
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim

import spinal.sim._
import spinal.core.sim._
import spinal.crypto.symmetric.des.TripleDESCore_Std



class SpinalSimTripleDESCoreStdTester extends FunSuite {


  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  // RTL to simulate
  val compiledRTL = SimConfig.compile(new TripleDESCore_Std())


  /**
    * Test 1
    */
  test("TripleDESCoreStd_notReleaseValid"){

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        SymmetricCryptoBlockIOSim.simWithValidNotRelease(dut.io, dut.clockDomain, enc = true )(TripleDES.block(verbose = false))
        SymmetricCryptoBlockIOSim.simWithValidNotRelease(dut.io, dut.clockDomain, enc = false)(TripleDES.block(verbose = false))

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }


  /**
    * Test 2
    */
  test("TripleDESCoreStd_releaseValid"){

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        SymmetricCryptoBlockIOSim.simWithValidReleased(dut.io, dut.clockDomain, enc = true )(TripleDES.block(verbose = false))
        SymmetricCryptoBlockIOSim.simWithValidReleased(dut.io, dut.clockDomain, enc = false)(TripleDES.block(verbose = false))

      }
    }
  }
}
