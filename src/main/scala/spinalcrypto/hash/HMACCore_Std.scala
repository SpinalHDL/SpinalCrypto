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
import spinal.lib.fsm._


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
  val hash = Bits(g.gHash.hashWidth)
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

  val hashTmp = Reg(Bits(128 bits))
  val cntWord = Reg(UInt(4 bits))

  val wordInBlock = (g.gHash.hashBlockWidth / g.gHash.dataWidth).value - 1

  /*
   * Default value
   */
  io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
  io.hashCore.cmd.size  := 0
  io.hashCore.cmd.last  := False
  io.hashCore.cmd.valid := False
  io.hashCore.init      := False

  io.hmacCore.rsp.valid := False
  io.hmacCore.rsp.hash  := io.hashCore.rsp.hash
  io.hmacCore.cmd.ready := False


  val keyWord  = cntWord.muxList(for(index <- 0 until 16) yield (15-index, io.hmacCore.cmd.key(index*32+32-1 downto index*32)))
  val hashWord = cntWord(1 downto 0).muxList( for(index <- 0 until 4) yield (3-index, hashTmp(index*32+32-1 downto index*32)))


  /**
    * State machine of the HMAC
    */
  val sm = new StateMachine{

    always{
      when(io.hmacCore.init){
        cntWord := 0
        io.hashCore.init := True
        goto(sLoadKeyIpad)
      }
    }

    val sIdle: State = new State with EntryPoint{
      whenIsActive{ /* Do nothing */}
    }

    val sLoadKeyIpad: State = new State{
      whenIsActive{
        io.hashCore.cmd.msg   := keyWord ^ HMACCoreSpec.ipad(g.gHash.dataWidth)
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid

        when(io.hashCore.cmd.ready){
          cntWord := cntWord + 1
          when(cntWord === wordInBlock){
            goto(sLoadMsg)
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
          cntWord := 0

          when(io.hmacCore.cmd.last){
            hashTmp := io.hashCore.rsp.hash
            io.hashCore.init := True
            goto(sLoadKeyOpad)
          }otherwise{
            io.hmacCore.cmd.ready := True
          }
        }
      }
    }

    val sLoadKeyOpad: State = new State{
      whenIsActive{
        io.hashCore.cmd.msg   := keyWord ^ HMACCoreSpec.opad(g.gHash.dataWidth)
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid

        when(io.hashCore.cmd.ready){
          cntWord := cntWord + 1
          when(cntWord === wordInBlock){
            goto(sLoadHash)
          }
        }
      }
    }

    val sLoadHash: State = new State{
      whenIsActive{
        io.hashCore.cmd.msg   := hashWord
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := cntWord === 3
        io.hashCore.cmd.size  := 3

        when(io.hashCore.cmd.ready){
          cntWord := cntWord + 1
          when(io.hashCore.cmd.last){
            io.hmacCore.cmd.ready := True
            io.hmacCore.rsp.valid := True
            io.hmacCore.rsp.hash  := io.hashCore.rsp.hash
            goto(sIdle)
          }
        }
      }
    }
  }
}
