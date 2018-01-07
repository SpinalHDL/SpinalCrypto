package spinal.crypto.symmetric.sim


import spinal.core._
import spinal.core.sim._
import spinal.crypto.symmetric._

import scala.util.Random



object SymmetricCryptoBlockIOSim {

  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  def initializeIO(dut: SymmetricCryptoBlockIO): Unit@suspendable ={
    dut.cmd.valid #= false
    dut.cmd.block.randomize()
    dut.cmd.key.randomize()
    if(dut.g.useEncDec) dut.cmd.enc.randomize()
  }

  /**
    * Between each operation the signal cmd_valid is release
    */
  def simWithValidReleased(dut: SymmetricCryptoBlockIO, clockDomain: ClockDomain, enc: Boolean, blockIn: BigInt = null, keyIn: BigInt = null)(refCrypto: (BigInt, BigInt, Boolean) => BigInt ): Unit@suspendable ={

    // Generate random input
    val block_in = if(blockIn == null) BigInt(dut.cmd.block.getWidth, Random) else blockIn
    val key      = if(keyIn == null)   BigInt(dut.cmd.key.getWidth, Random)   else keyIn

    // Send command
    dut.cmd.valid #= true
    dut.cmd.block #= block_in
    dut.cmd.key   #= key
    if(dut.g.useEncDec) dut.cmd.enc #= enc

    clockDomain.waitActiveEdge()

    // Wait response
    waitUntil(dut.rsp.valid.toBoolean == true)

    val rtlBlock_out = dut.rsp.block.toBigInt
    val refBlock_out = refCrypto(key, block_in, enc)

    // Check result
    assert(BigInt(rtlBlock_out.toByteArray.takeRight(dut.cmd.block.getWidth / 8)) == refBlock_out, s"Wrong result RTL ${bigIntToHex(rtlBlock_out)} !=  REF ${bigIntToHex(refBlock_out)}")

    clockDomain.waitActiveEdge()

    // release the command
    initializeIO(dut)

    clockDomain.waitActiveEdge()
  }


  /**
    * Between each operation the signal cmd_valid is not release
    */
  def simWithValidNotRelease(dut: SymmetricCryptoBlockIO, clockDomain: ClockDomain, enc: Boolean, blockIn: BigInt = null, keyIn: BigInt = null)(refCrypto: (BigInt, BigInt, Boolean) => BigInt ): Unit@suspendable ={

    // Generate random input
    val block_in = if(blockIn == null) BigInt(dut.cmd.block.getWidth, Random) else blockIn
    val key      = if(keyIn == null)   BigInt(dut.cmd.key.getWidth, Random)   else keyIn

    // Send command
    dut.cmd.valid #= true
    dut.cmd.block #= block_in
    dut.cmd.key   #= key
    if(dut.g.useEncDec) dut.cmd.enc #= enc

    clockDomain.waitActiveEdge()

    // Wait response
    waitUntil(dut.rsp.valid.toBoolean == true)

    val rtlBlock_out = dut.rsp.block.toBigInt
    val refBlock_out = refCrypto(key, block_in, enc)

    // Check result
    assert(BigInt(rtlBlock_out.toByteArray.takeRight(dut.cmd.block.getWidth / 8)) == refBlock_out, s"Wrong result RTL ${bigIntToHex(rtlBlock_out)} !=  REF ${bigIntToHex(refBlock_out)}")

    clockDomain.waitActiveEdge()
  }
}
