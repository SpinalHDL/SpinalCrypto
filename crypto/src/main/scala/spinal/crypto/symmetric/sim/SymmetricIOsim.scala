/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/  MIT Licence                      **
**                                                                           **
** Permission is hereby granted, free of charge, to any person obtaining a   **
** copy of this software and associated documentation files (the "Software"),**
** to deal in the Software without restriction, including without limitation **
** the rights to use, copy, modify, merge, publish, distribute, sublicense,  **
** and/or sell copies of the Software, and to permit persons to whom the     **
** Software is furnished to do so, subject to the following conditions:      **
**                                                                           **
** The above copyright notice and this permission notice shall be included   **
** in all copies or substantial portions of the Software.                    **
**                                                                           **
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS   **
** OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                **
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.    **
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY      **
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT **
** OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR  **
** THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                **
\*                                                                           */
package spinal.crypto.symmetric.sim

import spinal.crypto._

import spinal.core._
import spinal.core.sim._
import spinal.crypto.symmetric._

import scala.util.Random



object SymmetricCryptoBlockIOSim {

  /**
    * Initialize the IO with random value
    */
  def initializeIO(dut: SymmetricCryptoBlockIO): Unit ={
    dut.cmd.valid #= false
    dut.cmd.block.randomize()
    dut.cmd.key.randomize()
    if(dut.config.useEncDec) dut.cmd.enc.randomize()
  }


  /**
    * Symmetric Crypto Block IO simulation
    */
  def doSim(dut: SymmetricCryptoBlockIO, clockDomain: ClockDomain, enc: Boolean, blockIn: BigInt = null, keyIn: BigInt = null)(refCrypto: (BigInt, BigInt, Boolean) => BigInt ): Unit ={

    // Generate random input
    val block_in = if(blockIn == null) BigInt(dut.cmd.block.getWidth, Random) else blockIn
    val key      = if(keyIn == null)   BigInt(dut.cmd.key.getWidth, Random)   else keyIn

    // Send command
    dut.cmd.valid #= true
    dut.cmd.block #= block_in
    dut.cmd.key   #= key
    if(dut.config.useEncDec) dut.cmd.enc #= enc

    clockDomain.waitActiveEdge()

    // Wait response
    waitUntil(dut.rsp.valid.toBoolean == true)

    val rtlBlock_out = dut.rsp.block.toBigInt
    val refBlock_out = refCrypto(key, block_in, enc)

    // Check result
    assert(BigInt(rtlBlock_out.toByteArray.takeRight(dut.cmd.block.getWidth / 8)) == BigInt(refBlock_out.toByteArray.takeRight(dut.cmd.block.getWidth / 8)) , s"Wrong result RTL ${BigIntToHexString(rtlBlock_out)} !=  REF ${BigIntToHexString(refBlock_out)}")


    // release the command valid between each transaction randomly
    clockDomain.waitActiveEdge()

    if(Random.nextBoolean()){
      initializeIO(dut)

      clockDomain.waitActiveEdge()
    }
  }
}
