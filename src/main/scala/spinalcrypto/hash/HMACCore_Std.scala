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



case class HMACCoreStdGeneric(keyWidth: BitCount = 512 bits,
                              dataWidth: BitCount = 32 bits,
                              hashWidth: BitCount = 128 bits)

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

  io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
  io.hashCore.cmd.size  := 0
  io.hashCore.cmd.last  := False
  io.hashCore.cmd.valid := False

  io.hashCore.init := False

  io.hmacCore.rsp.valid := io.hashCore.rsp.valid
  io.hmacCore.rsp.hash  := io.hashCore.rsp.hash
  io.hmacCore.cmd.ready := False



  val sm = new StateMachine{
    always{
      when(io.hmacCore.init){
        io.hashCore.init := True
        goto(sLoadKeyIpad)
      }
    }
    val sLoadKeyIpad: State = new State with EntryPoint{
      whenIsActive{

        io.hashCore.cmd.msg   := (io.hmacCore.cmd.key ^ HMAC.ipad(g.keyWidth))(31 downto 0)
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := False
        io.hashCore.cmd.size  := 0

        when(io.hmacCore.rsp.valid){
          io.hmacCore.cmd.ready := True
          goto(sLoadMsg)
        }
      }
    }

    val sLoadMsg: State = new State{
      whenIsActive{
        io.hashCore.cmd.msg   := io.hmacCore.cmd.msg
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := io.hmacCore.cmd.last
        io.hashCore.cmd.size  := io.hmacCore.cmd.size
        when(io.hashCore.rsp.valid){
          io.hmacCore.cmd.ready := True
          when(io.hmacCore.cmd.last){
            hashTmp := io.hashCore.rsp.hash
            io.hashCore.init := True
            goto(sLoadKeyOpad)
          }
        }

      }
    }

    val sLoadKeyOpad: State = new State{
      whenIsActive{

        io.hashCore.cmd.msg   := (io.hmacCore.cmd.key ^ HMAC.opad(g.keyWidth))(31 downto 0)
        io.hashCore.cmd.valid := io.hmacCore.cmd.valid
        io.hashCore.cmd.last  := False
        io.hashCore.cmd.size  := 0

        when(io.hmacCore.rsp.valid){
          io.hmacCore.cmd.ready := True

          goto(sLoadHash)
        }
      }
    }

    val sLoadHash: State = new State{
      whenIsActive{

      }
    }
  }


}
