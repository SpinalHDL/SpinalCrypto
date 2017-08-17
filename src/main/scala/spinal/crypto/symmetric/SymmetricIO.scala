/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/                                   **
**                                                                           **
**      This library is free software; you can redistribute it and/or        **
**    modify it under the terms of the GNU Lesser General Public             **
**    License as published by the Free Software Foundation; either           **
**    version 3.0 of the License, or (at your option) any later version.     **
**                                                                           **
**      This library is distributed in the hope that it will be useful,      **
**    but WITHOUT ANY WARRANTY; without even the implied warranty of         **
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      **
**    Lesser General Public License for more details.                        **
**                                                                           **
**      You should have received a copy of the GNU Lesser General Public     **
**    License along with this library.                                       **
\*                                                                           */
package spinal.crypto.symmetric

import spinal.core._
import spinal.lib._
import spinal.lib.bus.misc.BusSlaveFactory


/**
  * Symmetric Crypto block generiics
  * @param keyWidth Key width
  * @param blockWidth Block width
  * @param useEncDec Create a signal for the encryption/decryption
  */
case class SymmetricCryptoBlockGeneric(
              keyWidth  : BitCount,
              blockWidth: BitCount,
              useEncDec : Boolean = true){}


/**
  * Command interface for a symmetric block algo
  */
case class SymmetricCryptoBlockCmd(g: SymmetricCryptoBlockGeneric) extends Bundle {
  val key    = Bits(g.keyWidth)
  val block  = Bits(g.blockWidth)
  val enc    = if(g.useEncDec) Bool else null
}


/**
  * Response interface for a symmetric block algo
  */
case class SymmetricCryptoBlockRsp(g: SymmetricCryptoBlockGeneric) extends Bundle {
  val block = Bits(g.blockWidth)
}


/**
  * Interface used by a symmetric block algo
  */
case class SymmetricCryptoBlockIO(g: SymmetricCryptoBlockGeneric) extends Bundle with IMasterSlave {
  val cmd  = Stream(SymmetricCryptoBlockCmd(g))
  val rsp  = Flow(SymmetricCryptoBlockRsp(g))

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

    busCtrl.drive(cmd.enc, addr) // TODO if cmd.enc is null ????
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