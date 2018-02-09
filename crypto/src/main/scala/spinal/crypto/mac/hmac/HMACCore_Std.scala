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
package spinal.crypto.mac.hmac

import spinal.core._
import spinal.lib._
import spinal.lib.bus.misc.BusSlaveFactory
import spinal.lib.fsm._
import spinal.crypto.hash.{HashCoreConfig, HashCoreIO}


/**
  * HMAC specification
  */
object HMACCoreSpec{
  def ipad(width: BitCount): Bits = B("x" + "36" * (width.value/8))
  def opad(width: BitCount): Bits = B("x" + "5C" * (width.value/8))
}


/**
  * HMAC Configuration
  */
case class HMACCoreStdConfig (
  keyWidth : BitCount,
  gHash    : HashCoreConfig
)


/**
  * HMAC Cmd
  */
case class HMACCoreStdCmd(config: HMACCoreStdConfig) extends Bundle {
  val key  = Bits(config.keyWidth)
  val msg  = Bits(config.gHash.dataWidth)
  val size = UInt(log2Up(config.gHash.dataWidth.value / 8) bits)
}


/**
  * HMAC Rsp
  */
case class HMACCoreStdRsp(config: HMACCoreStdConfig) extends Bundle {
  val hmac = Bits(config.gHash.hashWidth)
}


/**
  * HMAC IO
  */
case class HMACCoreStdIO(config: HMACCoreStdConfig) extends Bundle with IMasterSlave {

  val init = Bool
  val cmd  = Stream(Fragment(HMACCoreStdCmd(config)))
  val rsp  = Flow(HMACCoreStdRsp(config))

  override def asMaster(): Unit = {
    master(cmd)
    slave(rsp)
    out(init)
  }

  /** Drive IO from a bus */
  def driveFrom(busCtrl: BusSlaveFactory, baseAddress: Int = 0) = new Area {

    var addr = baseAddress

    /* Write operation */

    busCtrl.driveMultiWord(cmd.msg,   addr)
    addr += (widthOf(cmd.msg)/32)*4

    busCtrl.driveMultiWord(cmd.key,   addr)
    addr += (widthOf(cmd.key)/32)*4

    busCtrl.drive(cmd.last, addr)
    addr += 4

    busCtrl.drive(cmd.size, addr)
    addr += 4

    val initReg = busCtrl.drive(init, addr) init(False)
    initReg.clearWhen(initReg)
    addr += 4

    val validReg = busCtrl.drive(cmd.valid, addr) init(False)
    validReg.clearWhen(cmd.ready)
    addr += 4

    /* Read operation */

    val hmac   = Reg(cloneOf(rsp.hmac))
    val rspValid = Reg(Bool) init(False) setWhen(rsp.valid)

    when(rsp.valid){
      hmac := rsp.hmac
    }

    busCtrl.onRead(addr){
      when(rspValid){
        rspValid := False
      }
    }

    busCtrl.read(rspValid, addr)
    addr += 4

    busCtrl.readMultiWord(hmac, addr)
    addr += (widthOf(hmac)/32)*4


    //manage interrupts
    val interruptCtrl = new Area {
      val doneIntEnable = busCtrl.createReadAndWrite(Bool, address = addr, 0) init(False)
      val doneInt       = doneIntEnable & !rsp.valid
      val interrupt     = doneInt
    }
  }
}


/**
  * HMAC is computed with the following formula :
  *
  *   ---------------------------------------------------
  *  |                                                   |
  *  | HMAC(m) = h{( K ^ opad ) ## h[(K ^ ipad) ## m]}   |
  *  |                                                   |
  *   ---------------------------------------------------
  *
  *     - h    : Hash function (MD5, SHA-1, SHA-2, ...)
  *     - K    : Secret key (key width = hash block width)
  *     - m    : The message
  *     - ##   : Concatenation
  *     - ipad : 0x3636..3636 (hash block width)
  *     - opad : 0x5C5C..5C5C (hash block width)
  *
  *  The key can be of any length :
  *     - Key  < hash block => Pad the key with 0x00 up to hash block
  *     - Key == hash block => Use the key as it is
  *     - key  > hash block => Hash the key and then pad with 0x00 up to hash block
  */
class HMACCore_Std(val config: HMACCoreStdConfig) extends Component {

  assert(config.keyWidth == config.gHash.hashBlockWidth, "For the moment, the key must have the same width than the hash block")

  val io = new Bundle {
    val hashCore = master(HashCoreIO(config.gHash))
    val hmacCore = slave(HMACCoreStdIO(config))
  }

  val symbolInBlock = (config.gHash.hashBlockWidth / config.gHash.dataWidth).value
  val symbolInHash  = (config.gHash.hashWidth / config.gHash.dataWidth).value

  val hashTmp   = Reg(Bits(config.gHash.hashWidth))
  val cntSymbol = Reg(UInt(log2Up(symbolInBlock) bits))

  /*
   * Default value
   */
  io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
  io.hashCore.cmd.size  := 0
  io.hashCore.cmd.last  := False
  io.hashCore.cmd.valid := False
  io.hashCore.init      := False

  io.hmacCore.rsp.valid := False
  io.hmacCore.rsp.hmac  := io.hashCore.rsp.digest
  io.hmacCore.cmd.ready := False


  val keySymbol  = io.hmacCore.cmd.key.subdivideIn(config.gHash.dataWidth).reverse(cntSymbol)
  val hashSymbol = hashTmp.subdivideIn(config.gHash.dataWidth).reverse(cntSymbol(log2Up(symbolInHash)-1 downto 0))


  /**
    * State machine of the HMAC
    */
  val sm = new StateMachine {

    val isIpad = Reg(Bool)
    val xPad   = isIpad ? HMACCoreSpec.ipad(config.gHash.dataWidth) | HMACCoreSpec.opad(config.gHash.dataWidth)

    always{
      when(io.hmacCore.init){
        goto(sIdle)
      }
    }

    val sIdle: State = new State with EntryPoint {
      whenIsActive{
        when(io.hmacCore.cmd.valid){
          cntSymbol := 0
          isIpad    := True
          goto(sInit)
        }
      }
    }

    val sInit: State = new State {
      whenIsActive{
        io.hashCore.init := True
        goto(sLoadKey)
      }
    }

    val sLoadKey: State = new State {
      whenIsActive{
        io.hashCore.cmd.msg   := keySymbol ^ xPad
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid

        when(io.hashCore.cmd.ready){
          cntSymbol := cntSymbol + 1
          when(cntSymbol === (symbolInBlock-1)){
            when(isIpad){
              isIpad := False
              goto(sLoadMsg)
            }otherwise{
              goto(sLoadHash)
            }
          }
        }
      }
    }

    val sLoadMsg: State = new State {
      whenIsActive{
        io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := io.hmacCore.cmd.last
        io.hashCore.cmd.size  := io.hmacCore.cmd.size

        when(io.hashCore.cmd.ready){
          cntSymbol := 0

          when(io.hmacCore.cmd.last){
            hashTmp := io.hashCore.rsp.digest
            goto(sInit)
          }otherwise{
            io.hmacCore.cmd.ready := True
          }
        }
      }
    }

    val sLoadHash: State = new State {
      whenIsActive{
        io.hashCore.cmd.msg   := hashSymbol
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := cntSymbol === (symbolInHash - 1)
        io.hashCore.cmd.size  := (default -> true)

        when(io.hashCore.cmd.ready){
          cntSymbol := cntSymbol + 1
          when(io.hashCore.cmd.last){
            io.hmacCore.cmd.ready := True
            io.hmacCore.rsp.valid := True
            io.hmacCore.rsp.hmac  := io.hashCore.rsp.digest
            goto(sIdle)
          }
        }
      }
    }
  }
}

