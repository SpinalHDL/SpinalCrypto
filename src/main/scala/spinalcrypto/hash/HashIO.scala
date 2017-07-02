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
package spinalcrypto.hash

import spinal.core._
import spinal.lib._
import spinal.lib.bus.misc.BusSlaveFactory


/**
  * Hash Core configuration
  */
case class HashCoreGeneric(dataWidth     : BitCount,
                           hashWidth     : BitCount,
                           hashBlockWidth: BitCount)


/**
  * Hash Core command
  */
case class HashCoreCmd(g: HashCoreGeneric) extends Bundle{
  val msg  = Bits(g.dataWidth)
  val size = UInt(log2Up(g.dataWidth.value / 8) bits)
}


/**
  * Hash Core response
  */
case class HashCoreRsp(g: HashCoreGeneric) extends Bundle{
  val digest = Bits(g.hashWidth)
}


/**
  * Hash Core IO
  */
case class HashCoreIO(g: HashCoreGeneric) extends Bundle with IMasterSlave{

  val init = in Bool
  val cmd  = Stream(Fragment(HashCoreCmd(g)))
  val rsp  = Flow(HashCoreRsp(g))

  override def asMaster() = {
    out(init)
    master(cmd)
    slave(rsp)
  }

  /** Drive IO from a bus */
  def driveFrom(busCtrl: BusSlaveFactory, baseAddress: Int = 0) = new Area {

    var addr = baseAddress

    /* Write operation */

    busCtrl.driveMultiWord(cmd.msg,   addr)
    addr += (widthOf(cmd.msg)/32)*4

    busCtrl.drive(cmd.size, addr)
    addr += 4

    busCtrl.drive(cmd.last, addr)
    addr += 4

    val initReg = busCtrl.drive(init, addr)
    initReg.clearWhen(!initReg)
    addr += 4

    val validReg = busCtrl.drive(cmd.valid, addr)
    validReg.clearWhen(cmd.ready)
    addr += 4

    /* Read operation */

    val digest   = Reg(cloneOf(rsp.digest))
    val rspValid = Reg(Bool) init(False) setWhen(rsp.valid)

    when(rsp.valid){
      digest := rsp.digest
    }

    busCtrl.onRead(addr){
      when(rspValid){
        rspValid := False
      }
    }

    busCtrl.read(rspValid, addr)
    addr += 4

    busCtrl.readMultiWord(digest, addr)
    addr += (widthOf(digest)/32)*4


    //manage interrupts
    val interruptCtrl = new Area {
      val doneIntEnable = busCtrl.createReadAndWrite(Bool, address = addr, 0) init(False)
      val doneInt       = doneIntEnable & !rsp.valid
      val interrupt     = doneInt
    }
  }
}