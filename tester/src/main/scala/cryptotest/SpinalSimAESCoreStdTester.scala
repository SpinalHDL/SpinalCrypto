package cryptotest

import org.scalatest.FunSuite
import ref.symmetric.AES
import spinal.crypto.symmetric.aes.AESCore_Std
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim

import spinal.core._
import spinal.sim._
import spinal.core.sim._


class SpinalSimAESCoreStdTester extends FunSuite {


  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  // RTL to simulate
  val compiledRTL_128 = SimConfig.compile(new AESCore_Std(128 bits))
  //val compiledRTL_192 = SimConfig.compile(new AESCore_Std(192 bits))
  //val compiledRTL_256 = SimConfig.compile(new AESCore_Std(256 bits))

  /**
    * Test 1 - 128 bits
    */
  test("AESCoreStd_128_notReleaseValid"){

    compiledRTL_128.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(2){

        SymmetricCryptoBlockIOSim.simWithValidNotRelease(dut.io, dut.clockDomain, enc = true )(AES.block(128, verbose = false))
        SymmetricCryptoBlockIOSim.simWithValidNotRelease(dut.io, dut.clockDomain, enc = false)(AES.block(128, verbose = false))

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }

  /**
    * Test 2 - 128 bits
    */
  test("AESCoreStd_128_releaseValid"){

    compiledRTL_128.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(2){

        SymmetricCryptoBlockIOSim.simWithValidReleased(dut.io, dut.clockDomain, enc = true )(AES.block(128, verbose = false))
        SymmetricCryptoBlockIOSim.simWithValidReleased(dut.io, dut.clockDomain, enc = false)(AES.block(128, verbose = false))

      }
    }
  }
}


