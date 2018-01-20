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

sealed trait EncryptionMode
case object ENCRYPT  extends EncryptionMode
case object DECRYPT  extends EncryptionMode
case object ENC_DEC  extends EncryptionMode


case class BCMO_Std_Generic(
  keyWidth   : Int,
  blockWidth : Int,
  useEncDec  : Boolean = true,
  ivWidth    : Int = -1
){}


object BCMO_Std_CmdMode extends SpinalEnum {
  val INIT, UPDATE = newElement()
}


case class BCMO_Std_Cmd(g: BCMO_Std_Generic) extends Bundle {
  val key    = Bits(g.keyWidth bits)
  val block  = Bits(g.blockWidth bits)
  val iv     = if(g.ivWidth != -1) Bits(g.ivWidth bits) else null
  val enc    = if(g.useEncDec) Bool else null
  val mode   = BCMO_Std_CmdMode()
}


case class BCMO_Std_Rsp(g: BCMO_Std_Generic) extends Bundle {
  val block = Bits(g.blockWidth bits)
}


case class BCMO_Std_IO(g: BCMO_Std_Generic) extends Bundle with IMasterSlave {

  val cmd  = Stream(BCMO_Std_Cmd(g))
  val rsp  = Flow(BCMO_Std_Rsp(g))

  override def asMaster(): Unit = {
    master(cmd)
    slave(rsp)
  }
}


/**
  * Electronic CodeBook (ECB) - Block Cipher
  *
  *           Plaintext           Plaintext
  *           ___|____            ___|____
  *  Key --> |  Algo  |  Key --> |  Algo  |  ...
  *          |________|          |________|
  *              |                    |
  *          Ciphertext           Ciphertext
  */
case class ECB_Std(g: SymmetricCryptoBlockGeneric, mode: EncryptionMode) extends Component{

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Generic(
      keyWidth   = g.keyWidth.value,
      blockWidth = g.blockWidth.value,
      useEncDec  = mode == ENC_DEC,
      ivWidth    = -1
    )))
    val core = master(SymmetricCryptoBlockIO(g))
  }

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.key   := io.bcmo.cmd.key
  io.core.cmd.block := io.bcmo.cmd.block

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := io.core.rsp.block

  mode match{
    case ENCRYPT =>
      if(io.core.g.useEncDec) io.core.cmd.enc := True
    case DECRYPT =>
      if(io.core.g.useEncDec) io.core.cmd.enc := False
    case ENC_DEC =>
      if(io.core.g.useEncDec) io.core.cmd.enc := io.bcmo.cmd.enc
  }
}


/**
  * Cipher Block Chainings (CBC) - Block Cipher
  *
  *           Plaintext          Plaintext
  *              |                   |
  *    IV ----> XOR       /-------> XOR
  *           ___|____   |        ___|____
  *  Key --> |  Algo  |  | Key-->|  Algo  |
  *          |________|  |       |________|
  *              |-------/           |------- ...
  *          Ciphertext          Ciphertext
  */
case class CBC_Std(g: SymmetricCryptoBlockGeneric, mode: EncryptionMode) extends Component{

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Generic(
      keyWidth   = g.keyWidth.value,
      blockWidth = g.blockWidth.value,
      useEncDec  = mode == ENC_DEC,
      ivWidth    = g.blockWidth.value)))
    val core = master(SymmetricCryptoBlockIO(g))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT

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

/**
  * Output Feedback Mode (OFB) - Stream cipher
  *
  *               IV       /---------------\
  *             ___|____   |            ___|____
  *    Key --> |  Algo  |  |     Key-->|  Algo  |
  *            |________|  |           |________|
  *                |-------/                |----- ...
  * Plaintext --> XOR        Plaintext --> XOR
  *                |                        |
  *            Ciphertext               Ciphertext
  */
case class OFB_Std(g: SymmetricCryptoBlockGeneric, mode: EncryptionMode) extends Component{

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Generic(
      keyWidth   = g.keyWidth.value,
      blockWidth = g.blockWidth.value,
      useEncDec  = mode == ENC_DEC,
      ivWidth    = g.blockWidth.value
    )))

    val core = master(SymmetricCryptoBlockIO(g))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT


  if(g.useEncDec) io.core.cmd.enc := (if(mode == ENC_DEC) io.bcmo.cmd.enc else Bool(mode == ENCRYPT))

  val tmpKey = Reg(Bits(g.blockWidth))

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.block := (isInit) ? io.bcmo.cmd.iv | tmpKey
  io.core.cmd.key   := io.bcmo.cmd.key

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := io.core.rsp.block ^ io.bcmo.cmd.block

  when(io.core.rsp.valid){
    tmpKey := io.core.rsp.block
  }
}


/**
  * Cipher Feedback (CFB) - Stream cipher
  *
  *               IV       /---------------\
  *             ___|____   |            ___|____
  *    Key --> |  Algo  |  |     Key-->|  Algo  |
  *            |________|  |           |________|
  *                |       |                |
  * Plaintext --> XOR      | Plaintext --> XOR
  *                |-------/                |---- ...
  *            Ciphertext               Ciphertext
  */
case class CFB_Std(g: SymmetricCryptoBlockGeneric, mode: EncryptionMode) extends Component{

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Generic(
      keyWidth   = g.keyWidth.value,
      blockWidth = g.blockWidth.value,
      useEncDec  = mode == ENC_DEC,
      ivWidth    = g.blockWidth.value
    )))

    val core = master(SymmetricCryptoBlockIO(g))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT

  if(g.useEncDec) io.core.cmd.enc := (if(mode == ENC_DEC) io.bcmo.cmd.enc else Bool(mode == ENCRYPT))

  val tmpKey = Reg(Bits(g.blockWidth))
  val cipher = Bits(g.blockWidth)

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.block := (isInit) ? io.bcmo.cmd.iv | tmpKey
  io.core.cmd.key   := io.bcmo.cmd.key

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := cipher

  cipher := io.core.rsp.block ^ io.bcmo.cmd.block

  when(io.core.rsp.valid){
    tmpKey := cipher
  }
}


/**
  * Counter (CTR) - Stream cipher
  *
  *         (IV ## Counter)     (IV ## Counter + 1)
  *           ___|____             ___|____
  *  Key --> |  Algo  |   Key --> |  Algo  |  ...
  *          |________|           |________|
  *              |                    |
  * Plaintext ->XOR      Plaintext ->XOR
  *              |                    |
  *          Ciphertext           Ciphertext
  */
class CTR_Std(g: SymmetricCryptoBlockGeneric, ivWidth: Int,  f_inc : Bits => Bits, initCounter: BigInt, mode: EncryptionMode) extends Component {

  assert(ivWidth > 0 && ivWidth < g.blockWidth.value)

  val io = new Bundle {
    val bcmo = slave(BCMO_Std_IO(BCMO_Std_Generic(
      keyWidth   = g.keyWidth.value,
      blockWidth = g.blockWidth.value,
      useEncDec  = mode == ENC_DEC,
      ivWidth    = ivWidth
    )))

    val core = master(SymmetricCryptoBlockIO(g))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT

  assert(g.blockWidth.value - io.bcmo.g.ivWidth > 0)
  val counter = Reg(Bits((g.blockWidth.value - io.bcmo.g.ivWidth) bits))
  val counterTmp = cloneOf(counter)

  when(isInit){
    counterTmp := initCounter
  }otherwise{
    counterTmp := f_inc(counter)
  }

  counter := counterTmp

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.key   := io.bcmo.cmd.key
  io.core.cmd.block := io.bcmo.cmd.iv ## counterTmp

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := io.core.rsp.block ^ io.bcmo.cmd.block

  if(g.useEncDec) io.core.cmd.enc := True

}

object CTR_Std{

  def apply(g: SymmetricCryptoBlockGeneric, ivWidth: Int, mode: EncryptionMode, initCounter: BigInt = 0): CTR_Std ={
    new CTR_Std(g, ivWidth, x => (x.asUInt + 1).asBits, initCounter, mode)
  }

  def apply(g: SymmetricCryptoBlockGeneric, ivWidth: Int, mode: EncryptionMode, f_inc : Bits => Bits, initCounter: BigInt): CTR_Std = {
    new CTR_Std(g, ivWidth, f_inc, initCounter, mode)
  }
}



object PlayWithBCMO{

  import spinal.crypto.symmetric.des._

  class TestModeOperation() extends Component{

    val io = new Bundle{
      val ecb = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = true,
        ivWidth    = 64
      )))
      val cbc = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = true,
        ivWidth    = 64
      )))
      val ofb = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = false,
        ivWidth    = 64
      )))
      val cfb = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = false,
        ivWidth    = 64
      )))
      val ctr = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = false,
        ivWidth    = 32
      )))
    }

    val ecb = new Area {
      val core = new DESCore_Std()
      val chaining = ECB_Std(core.io.g, ENC_DEC)
      chaining.io.core <> core.io
      chaining.io.bcmo <> io.ecb
    }

    val cbc = new Area {
      val core = new DESCore_Std()
      val chaining = CBC_Std(core.io.g, ENC_DEC)
      chaining.io.core <> core.io
      chaining.io.bcmo <> io.cbc
    }

    val ofb = new Area {
      val core = new DESCore_Std()
      val chaining = OFB_Std(core.io.g, ENCRYPT)
      chaining.io.core <> core.io
      chaining.io.bcmo <> io.ofb
    }

    val cfb = new Area {
      val core = new DESCore_Std()
      val chaining = CFB_Std(core.io.g,  ENCRYPT)
      chaining.io.core <> core.io
      chaining.io.bcmo <> io.cfb
    }

    val ctr = new Area {
      val core = new DESCore_Std()
      val chaining = CTR_Std(core.io.g, io.ctr.g.ivWidth, ENCRYPT)
      chaining.io.core <> core.io
      chaining.io.bcmo <> io.ctr
    }

  }

  def main(args: Array[String]): Unit = {
    SpinalVhdl(new TestModeOperation()).printPruned()
  }
}
