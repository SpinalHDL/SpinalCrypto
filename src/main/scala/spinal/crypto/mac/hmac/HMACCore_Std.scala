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
package spinal.crypto.mac.hmac

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._
import spinal.crypto.hash.{HashCoreGeneric, HashCoreIO}


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
case class HMACCoreStdGeneric(keyWidth: BitCount,
                              gHash   : HashCoreGeneric)


/**
  * HMAC Cmd
  */
case class HMACCoreStdCmd(g: HMACCoreStdGeneric) extends Bundle{
  val key  = Bits(g.keyWidth)
  val msg  = Bits(g.gHash.dataWidth)
  val size = UInt(log2Up(g.gHash.dataWidth.value / 8) bits)
}


/**
  * HMAC Rsp
  */
case class HMACCoreStdRsp(g: HMACCoreStdGeneric) extends Bundle{
  val hmac = Bits(g.gHash.hashWidth)
}


/**
  * HMAC IO
  */
case class HMACCoreStdIO(g: HMACCoreStdGeneric) extends Bundle with IMasterSlave{

  val init = Bool
  val cmd  = Stream(Fragment(HMACCoreStdCmd(g)))
  val rsp  = Flow(HMACCoreStdRsp(g))

  override def asMaster(): Unit = {
    master(cmd)
    slave(rsp)
    out(init)
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
class HMACCore_Std(val g: HMACCoreStdGeneric) extends Component {

  assert(g.keyWidth == g.gHash.hashBlockWidth, "For the moment, the key must have the same width than the hash block")

  val io = new Bundle{
    val hashCore = master(HashCoreIO(g.gHash))
    val hmacCore = slave(HMACCoreStdIO(g))
  }

  val symbolInBlock = (g.gHash.hashBlockWidth / g.gHash.dataWidth).value
  val symbolInHash  = (g.gHash.hashWidth / g.gHash.dataWidth).value

  val hashTmp   = Reg(Bits(g.gHash.hashWidth))
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


  val keySymbol  = io.hmacCore.cmd.key.subdivideIn(g.gHash.dataWidth)(cntSymbol)
  val hashSymbol = hashTmp.subdivideIn(g.gHash.dataWidth)(cntSymbol(log2Up(symbolInHash)-1 downto 0))


  /**
    * State machine of the HMAC
    */
  val sm = new StateMachine{

    val isIpad = Reg(Bool)
    val xPad   = isIpad ? HMACCoreSpec.ipad(g.gHash.dataWidth) | HMACCoreSpec.opad(g.gHash.dataWidth)

    always{
      when(io.hmacCore.init){
        cntSymbol := 0
        isIpad    := True
        io.hashCore.init := True
        goto(sLoadKey)
      }
    }

    val sIdle: State = new State with EntryPoint{
      whenIsActive{ /* Do nothing */}
    }

    val sLoadKey: State = new State{
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

    val sLoadMsg: State = new State{
      whenIsActive{
        io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := io.hmacCore.cmd.last
        io.hashCore.cmd.size  := io.hmacCore.cmd.size

        when(io.hashCore.cmd.ready){
          cntSymbol := 0

          when(io.hmacCore.cmd.last){
            hashTmp := io.hashCore.rsp.digest
            io.hashCore.init := True
            goto(sLoadKey)
          }otherwise{
            io.hmacCore.cmd.ready := True
          }
        }
      }
    }

    val sLoadHash: State = new State{
      whenIsActive{
        io.hashCore.cmd.msg   := hashSymbol
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := cntSymbol === (symbolInHash-1)
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

