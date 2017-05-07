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
package spinalcrypto.symmetric

import spinal.core._
import spinal.lib._

import spinalcrypto.symmetric.des._

trait EncryptionMode
case object ENCRYPT  extends EncryptionMode
case object DECRYPT  extends EncryptionMode
case object ENC_DEC  extends EncryptionMode


case class BCMO_Generic(keyWidth   : BitCount,
                        blockWidth : BitCount,
                        useEncDec  : Boolean = true){}


object BCMO_CmdMode extends SpinalEnum{
  val INIT, UPDATE = newElement()
}

case class BCMO_Cmd(g: BCMO_Generic) extends Bundle {
  val key    = Bits(g.keyWidth)
  val block  = Bits(g.blockWidth)
  val iv     = Bits(g.blockWidth)
  val enc    = if(g.useEncDec) Bool else null
  val mode   = BCMO_CmdMode()
}

case class BCMO_Rsp(g: BCMO_Generic) extends Bundle {
  val block = Bits(g.blockWidth)
}


case class BCMO_IO(g: BCMO_Generic) extends Bundle with IMasterSlave {
  val cmd  = Stream(BCMO_Cmd(g))
  val rsp  = Flow(BCMO_Rsp(g))

  override def asMaster(): Unit = {
    master(cmd)
    slave(rsp)
  }
}




case class CBC(g: SymmetricCryptoCoreGeneric, mode: EncryptionMode) extends Component{

  val io = new Bundle{
    val bcmo = slave (BCMO_IO(BCMO_Generic(keyWidth   = g.keyWidth,
                                           blockWidth = g.blockWidth,
                                           useEncDec  = mode == ENC_DEC)))
    val core = master(SymmetricCryptoCoreIO(g))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_CmdMode.INIT
  val isUpdate = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_CmdMode.UPDATE

  val tmpBlock = Reg(Bits(g.blockWidth))

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.key   := io.bcmo.cmd.key

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid

  mode match{

    case ENCRYPT =>

      if(io.core.g.useEncDec) io.core.cmd.enc := True

      io.core.cmd.block := io.bcmo.cmd.block ^ (isInit ? io.bcmo.cmd.iv | tmpBlock)

      io.bcmo.rsp.block := io.core.rsp.block

      when(io.core.rsp.valid){
        tmpBlock := io.core.rsp.block
      }

    case DECRYPT =>

      if(io.core.g.useEncDec) io.core.cmd.enc := False

      io.core.cmd.block := io.bcmo.cmd.block

      io.bcmo.rsp.block := io.core.rsp.block ^ (isInit ? io.bcmo.cmd.iv | tmpBlock)

      when(io.bcmo.cmd.valid){
        tmpBlock := io.bcmo.cmd.block
      }

    case ENC_DEC =>

      assert(io.core.g.useEncDec, "This core doesn't support encryption/decryption mode")

      io.core.cmd.enc   := io.bcmo.cmd.enc

      io.core.cmd.block := io.bcmo.cmd.enc ? (io.bcmo.cmd.block ^ (isInit ? io.bcmo.cmd.iv | tmpBlock)) | (io.bcmo.cmd.block)

      io.bcmo.rsp.block := io.bcmo.cmd.enc ? (io.core.rsp.block) | (io.core.rsp.block ^ (isInit ? io.bcmo.cmd.iv | tmpBlock))

      when(io.bcmo.cmd.valid){
        tmpBlock := io.bcmo.cmd.enc ? io.core.rsp.block | io.bcmo.cmd.block
      }
  }
}


// TODO implement CFB
case class CFB()
// TODO implement OFB
case class OFB()
// TODO implement CTR
case class CTR()



object PlayWithBCMO{

  class TestCBC() extends Component{

    val io = slave(BCMO_IO(BCMO_Generic(keyWidth   = 64 bits,
      blockWidth = 64 bits,
      useEncDec  = true)))

    val desCore = new DESCore_Std()
    val desModule = CBC(desCore.io.g, ENC_DEC)
    desModule.io.core <> desCore.io

    desModule.io.bcmo <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalVhdl(new TestCBC()).printPruned()
  }
}
