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
import spinalcrypto.hash.md5._


object HMAC{
  def ipad(width: BitCount): Bits = B("x" + "36" * (width.value/8))
  def opad(width: BitCount): Bits = B("x" + "5C" * (width.value/8))
}



case class HMACCoreStdGeneric(keyWidth  : BitCount = 512 bits,
                              dataWidth : BitCount = 32  bits,
                              hashWidth : BitCount = 128 bits)

case class HMACCoreStdCmd(g: HMACCoreStdGeneric) extends Bundle{
  val key  = Bits(g.keyWidth)
  val msg  = Bits(g.dataWidth)
  val size = UInt(2 bits)
}

case class HMACCoreStdRsp(g: HMACCoreStdGeneric) extends Bundle{
  val hash = Bits(128 bits)
}

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
  *  HMAC(m) = k[ ( k ^ opad ) ## h((k ^ ipad) ## m) ]
  */
class HMACCore_Std(g: HMACCoreStdGeneric = HMACCoreStdGeneric()) extends Component {

  val io = new Bundle{
    val hashCore = master(MD5CoreStdIO(new MD5CoreStdGeneric()))
    val hmacCore = slave(HMACCoreStdIO(g))
  }

  val hashTmp = Reg(Bits(128 bits))
  val cntByte = Reg(UInt(4 bits))

  io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
  io.hashCore.cmd.size  := 0
  io.hashCore.cmd.last  := False
  io.hashCore.cmd.valid := False

  io.hashCore.init := False

  io.hmacCore.rsp.valid := False
  io.hmacCore.rsp.hash  := io.hashCore.rsp.hash
  io.hmacCore.cmd.ready := False


  val keyWord  = cntByte.muxList(for(index <- 0 until 16) yield (15-index, io.hmacCore.cmd.key(index*32+32-1 downto index*32)))
  val hashWord = cntByte(1 downto 0).muxList( for(index <- 0 until 4) yield (3-index, hashTmp(index*32+32-1 downto index*32)))


  val sm = new StateMachine{

    always{
      when(io.hmacCore.init){
        cntByte := 0
        io.hashCore.init := True
        goto(sLoadKeyIpad)
      }
    }

    val sIdle: State = new State with EntryPoint{
      whenIsActive{}
    }

    val sLoadKeyIpad: State = new State{
      whenIsActive{

        io.hashCore.cmd.msg   := keyWord ^ HMAC.ipad(32 bits)
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := False
        io.hashCore.cmd.size  := 0

        when(io.hashCore.cmd.ready){
          cntByte := cntByte + 1
          when(cntByte === 15){
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
          cntByte := 0

          when(io.hmacCore.cmd.last){
            hashTmp := io.hashCore.rsp.hash
            io.hashCore.init := True
           // io.hashCore.cmd.valid := False
            goto(sLoadKeyOpad)
          }otherwise{
            io.hmacCore.cmd.ready := True
          }
        }

      }
    }

    val sLoadKeyOpad: State = new State{
      whenIsActive{

        io.hashCore.cmd.msg   := keyWord ^ HMAC.opad(32 bits)
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := False
        io.hashCore.cmd.size  := 3

        when(io.hashCore.cmd.ready){
          cntByte := cntByte + 1
          when(cntByte === 15){
            goto(sLoadHash)
          }
        }
      }
    }

    val sLoadHash: State = new State{
      whenIsActive{

        io.hashCore.cmd.msg   := hashWord
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := cntByte === 3
        io.hashCore.cmd.size  := 3

        when(io.hashCore.cmd.ready){
          cntByte := cntByte + 1
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

