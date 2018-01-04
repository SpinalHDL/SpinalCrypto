package cryptotest

import lib.assymetric.DES
import org.scalatest.FunSuite
import spinal.core._
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.symmetric.des.DESCore_Std

import scala.util.Random



class SpinalSimDESCoreSTDTester extends FunSuite {


  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  // RTL to simulate
  val compiledRTL = SimConfig.compile(new DESCore_Std())


  /**
    * Test 1
    */
  test("DESCoreSTD_notReleaseValid"){

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        // Generate random input
        val plain = BigInt(64, Random)
        val key   = BigInt(64, Random)

        // Encryption
        dut.io.cmd.valid #= true
        dut.io.cmd.block #= plain
        dut.io.cmd.enc   #= true
        dut.io.cmd.key   #= key

        dut.clockDomain.waitActiveEdge()

        waitUntil(dut.io.rsp.valid.toBoolean == true)


        val rtlCipher = dut.io.rsp.block.toBigInt
        val refCipher = DES.encryptBlock(key, plain)

        assert(BigInt(rtlCipher.toByteArray.takeRight(8)) == refCipher, s"Wrong Cipher RTL ${bigIntToHex(rtlCipher)} !=  REF ${bigIntToHex(refCipher)}")

        dut.clockDomain.waitActiveEdge()

        // Decryption
        dut.io.cmd.valid #= true
        dut.io.cmd.block #= rtlCipher
        dut.io.cmd.enc   #= false
        dut.io.cmd.key   #= key

        dut.clockDomain.waitActiveEdge()

        waitUntil(dut.io.rsp.valid.toBoolean == true)

        val rtlPlain = dut.io.rsp.block.toBigInt
        assert(rtlPlain == plain, s"Wrong Plain RTL ${bigIntToHex(rtlPlain)} !=  REF ${bigIntToHex(plain)}")

        dut.clockDomain.waitActiveEdge()

      }
    }
  }

  /**
    * Test 2
    */
  test("DESCoreSTD_releaseValid"){

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        // Generate random number
        val plain = BigInt(64, Random)
        val key   = BigInt(64, Random)


        // Encryption
        dut.io.cmd.valid #= true
        dut.io.cmd.block #= plain
        dut.io.cmd.enc   #= true
        dut.io.cmd.key   #= key

        dut.clockDomain.waitActiveEdge()

        waitUntil(dut.io.rsp.valid.toBoolean == true)

        val rtlCipher = dut.io.rsp.block.toBigInt
        val refCipher = DES.encryptBlock(key, plain)

        assert(BigInt(rtlCipher.toByteArray.takeRight(8)) == refCipher, s"Wrong Cipher RTL ${bigIntToHex(rtlCipher)} !=  REF ${bigIntToHex(refCipher)}")

        dut.clockDomain.waitActiveEdge()

        dut.io.cmd.valid #= false

        dut.clockDomain.waitActiveEdge()

        // Decryption
        dut.io.cmd.valid #= true
        dut.io.cmd.block #= rtlCipher
        dut.io.cmd.enc   #= false
        dut.io.cmd.key   #= key

        dut.clockDomain.waitActiveEdge()

        waitUntil(dut.io.rsp.valid.toBoolean == true)

        val rtlPlain = dut.io.rsp.block.toBigInt

        assert(rtlPlain == plain, s"Wrong Plain RTL ${bigIntToHex(rtlPlain)} !=  REF ${bigIntToHex(plain)}")

        dut.clockDomain.waitActiveEdge()

        dut.io.cmd.valid #= false

        dut.clockDomain.waitActiveEdge()
      }
    }
  }
}
