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
package spinal.crypto.hash

import spinal.core._
import spinal.crypto.padding.PaddingIOConfig
import spinal.lib._
import spinal.lib.bus.misc.BusSlaveFactory
import spinal.lib.fsm._

trait EndiannessMode
object BIG_endian    extends EndiannessMode
object LITTLE_endian extends EndiannessMode

/**
  * Hash Core configuration
  */
case class HashCoreConfig (
  dataWidth      : BitCount,
  hashWidth      : BitCount,
  hashBlockWidth : BitCount
){
  def getPaddingIOConfig = PaddingIOConfig(
    dataCmdWidth = dataWidth,
    dataRspWidth = hashBlockWidth,
    symbolWidth  = 8 bits
  )
}


/**
  * Hash Core command
  */
case class HashCoreCmd(config: HashCoreConfig) extends Bundle {
  val msg  = Bits(config.dataWidth)
  val size = UInt(log2Up(config.dataWidth.value / 8) bits)
}


/**
  * Hash Core response
  */
case class HashCoreRsp(config: HashCoreConfig) extends Bundle {
  val digest = Bits(config.hashWidth)
}


/**
  * Hash Core IO
  */
case class HashCoreIO(config: HashCoreConfig) extends Bundle with IMasterSlave {

  val init = in Bool()
  val cmd  = Stream(Fragment(HashCoreCmd(config)))
  val rsp  = Flow(HashCoreRsp(config))

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
    addr += (widthOf(cmd.msg) / 32) * 4

    busCtrl.drive(cmd.size, addr)
    addr += 4

    busCtrl.drive(cmd.last, addr)
    addr += 4

    val initReg = busCtrl.drive(init, addr) init(False)
    initReg.clearWhen(initReg)
    addr += 4

    val validReg = busCtrl.drive(cmd.valid, addr) init(False)
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
    addr += (widthOf(digest) / 32) * 4


    //manage interrupts
    val interruptCtrl = new Area {
      val doneIntEnable = busCtrl.createReadAndWrite(Bool, address = addr, 0) init(False)
      val doneInt       = doneIntEnable & !rsp.valid
      val interrupt     = doneInt
    }
  }
}


/**
  * Hash Engine command
  */
case class HashEngineCmd(blockSize: BitCount) extends Bundle {
  val message = Bits(blockSize)
}


/**
  * Hash Engine response
  */
case class HashEngineRsp(digestSize: BitCount) extends Bundle {
  val digest = Bits(digestSize)
}


/**
  * Hash Engine IO
  */
case class HashEngineIO(blockSize: BitCount, digestSize: BitCount) extends Bundle with IMasterSlave {

  val init = Bool
  val cmd  = Stream(HashEngineCmd(blockSize))
  val rsp  = Flow(HashEngineRsp(digestSize))

  override def asMaster() = {
    out(init)
    master(cmd)
    slave(rsp)
  }
}

