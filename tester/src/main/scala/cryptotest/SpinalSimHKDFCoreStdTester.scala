package cryptotest


import org.scalatest.FunSuite
import spinal.core._
import spinal.lib._
import spinal.core.sim._
import spinal.crypto.Endianness
import spinal.crypto.hash.sha2._
import spinal.crypto.kdf.hkdf.HKDFCore_Std

import scala.util.Random


class HKDF_SHA256_Tester() extends Component {

  val ikmWidth = 176 bits

  val io = new Bundle{
    val init = in Bool
    val valid = in Bool
    val ikm   = in Bits(ikmWidth)
    val salt  = in Bits(512 bits)
    val info  = in Bits(32 bits)
    val l     = in Bits(32 bits)
  }

  val sha  = new SHA2Core_Std(SHA2_256)
  val hkdf = new HKDFCore_Std(sha.configCore,  sizeIKM  = ikmWidth)

  hkdf.io.hash <> sha.io
  hkdf.io.ikm    := io.ikm
  hkdf.io.salt   := io.salt
  hkdf.io.info   := io.info
  hkdf.io.l      := io.l
  hkdf.io.valid  := io.valid
  hkdf.io.init   := io.init
}



class SpinalSimHKDFCoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withWave(4).withConfig(SpinalConfig(inlineRom = true)).compile(new HKDF_SHA256_Tester())

  val NBR_ITERATION = 200

  /**
    * Test
    *
    * https://cryptii.com/pipes/hmac
    *
    *
Hash = SHA-256
IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
salt = 000102030405060708090a0b0c
info = f0f1f2f3f4f5f6f7f8f9
L    = 42
PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865

    */
  test("HKDF_SHA256"){

    compiledRTL.doSim{ dut =>


      dut.clockDomain.forkStimulus(2)

      dut.io.init  #= false
      dut.io.valid #= false

      // init HMAC
      dut.clockDomain.waitActiveEdge()
      dut.io.init #= true
      dut.clockDomain.waitActiveEdge()
      dut.io.init #= false
      dut.clockDomain.waitActiveEdge()


      // first step extract test
      dut.io.valid #= true
      dut.io.salt  #= BigInt("000102030405060708090a0b0c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16)
      dut.io.ikm   #= BigInt("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 16)



      dut.clockDomain.waitActiveEdge(500)
    }
  }
}