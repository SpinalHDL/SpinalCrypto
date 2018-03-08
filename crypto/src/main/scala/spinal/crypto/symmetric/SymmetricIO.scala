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
package spinal.crypto.symmetric

import spinal.core._
import spinal.lib._
import spinal.lib.bus.misc.BusSlaveFactory


/**
  * Symmetric Crypto block generiics
  * @param keyWidth   Key width
  * @param blockWidth Block width
  * @param useEncDec  Create a signal for the encryption/decryption
  */
case class SymmetricCryptoBlockConfig(
  keyWidth   : BitCount,
  blockWidth : BitCount,
  useEncDec  : Boolean = true
)


/**
  * Command interface for a symmetric block algo
  */
case class SymmetricCryptoBlockCmd(config: SymmetricCryptoBlockConfig) extends Bundle {
  val key    = Bits(config.keyWidth)
  val block  = Bits(config.blockWidth)
  val enc    = if(config.useEncDec) Bool else null
}


/**
  * Response interface for a symmetric block algo
  */
case class SymmetricCryptoBlockRsp(config: SymmetricCryptoBlockConfig) extends Bundle {
  val block = Bits(config.blockWidth)
}


/**
  * Interface used by a symmetric block algo
  */
case class SymmetricCryptoBlockIO(config: SymmetricCryptoBlockConfig) extends Bundle with IMasterSlave {

  val cmd  = Stream(SymmetricCryptoBlockCmd(config))
  val rsp  = Flow(SymmetricCryptoBlockRsp(config))

  override def asMaster() = {
    master(cmd)
    slave(rsp)
  }

  /** Drive IO from a bus */
  def driveFrom(busCtrl: BusSlaveFactory, baseAddress: Int = 0) = new Area {

    var addr = baseAddress

    /* Write operation */

    busCtrl.driveMultiWord(cmd.key,   addr)
    addr += (widthOf(cmd.key)/32)*4

    busCtrl.driveMultiWord(cmd.block, addr)
    addr += (widthOf(cmd.block)/32)*4

    if(config.useEncDec) busCtrl.drive(cmd.enc, addr)
    addr += 4

    val validReg = busCtrl.drive(cmd.valid, addr) init(False)
    validReg.clearWhen(cmd.ready)
    addr += 4

    /* Read operation */

    val block    = Reg(cloneOf(rsp.block))
    val rspValid = Reg(Bool) init(False) setWhen(rsp.valid)

    when(rsp.valid){
      block := rsp.block
    }

    busCtrl.onRead(addr){
      when(rspValid){
        rspValid := False
      }
    }

    busCtrl.read(rspValid, addr)
    addr += 4

    busCtrl.readMultiWord(block, addr)
    addr += (widthOf(block)/32)*4


    //manage interrupts
    val interruptCtrl = new Area {
      val doneIntEnable = busCtrl.createReadAndWrite(Bool, address = addr, 0) init(False)
      val doneInt       = doneIntEnable & !rsp.valid
      val interrupt     = doneInt
    }
  }
}