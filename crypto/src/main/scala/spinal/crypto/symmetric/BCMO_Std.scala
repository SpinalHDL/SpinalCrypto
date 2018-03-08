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

import spinal.core.{assert, _}
import spinal.lib._


sealed trait EncryptionMode
case object ENCRYPT  extends EncryptionMode
case object DECRYPT  extends EncryptionMode
case object ENC_DEC  extends EncryptionMode


case class BCMO_Std_Config(
  keyWidth   : Int,
  blockWidth : Int,
  useEncDec  : Boolean = true,
  ivWidth    : Int = -1
)


object BCMO_Std_CmdMode extends SpinalEnum {
  val INIT, UPDATE = newElement()
}


case class BCMO_Std_Cmd(config: BCMO_Std_Config) extends Bundle {
  val key    = Bits(config.keyWidth bits)
  val block  = Bits(config.blockWidth bits)
  val iv     = if(config.ivWidth != -1) Bits(config.ivWidth bits) else null
  val enc    = if(config.useEncDec) Bool else null
  val mode   = BCMO_Std_CmdMode()
}


case class BCMO_Std_Rsp(config: BCMO_Std_Config) extends Bundle {
  val block = Bits(config.blockWidth bits)
}


case class BCMO_Std_IO(config: BCMO_Std_Config) extends Bundle with IMasterSlave {

  val cmd  = Stream(BCMO_Std_Cmd(config))
  val rsp  = Flow(BCMO_Std_Rsp(config))

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
case class ECB_Std(config: SymmetricCryptoBlockConfig, chainningMode: EncryptionMode) extends Component {

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = config.keyWidth.value,
      blockWidth = config.blockWidth.value,
      useEncDec  = chainningMode == ENC_DEC,
      ivWidth    = -1
    )))
    val core = master(SymmetricCryptoBlockIO(config))
  }

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.key   := io.bcmo.cmd.key
  io.core.cmd.block := io.bcmo.cmd.block

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := io.core.rsp.block

  val isEnc = chainningMode match{
    case ENCRYPT => True
    case DECRYPT => False
    case ENC_DEC =>
      assert(io.core.config.useEncDec, "This core doesn't support encryption/decryption mode")
      io.bcmo.cmd.enc
  }

  if(io.core.config.useEncDec) io.core.cmd.enc := isEnc
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
case class CBC_Std(config: SymmetricCryptoBlockConfig, chainningMode: EncryptionMode) extends Component {

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = config.keyWidth.value,
      blockWidth = config.blockWidth.value,
      useEncDec  = chainningMode == ENC_DEC,
      ivWidth    = config.blockWidth.value)))
    val core = master(SymmetricCryptoBlockIO(config))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT

  val tmpBlock = Reg(Bits(config.blockWidth))

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.key   := io.bcmo.cmd.key

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid

  val isEnc = chainningMode match{
    case ENCRYPT =>  True
    case DECRYPT =>  False
    case ENC_DEC =>
      assert(io.core.config.useEncDec, "This core doesn't support encryption/decryption mode")
      io.bcmo.cmd.enc
  }

  if(io.core.config.useEncDec) io.core.cmd.enc := isEnc

  val xorValue = isInit ? io.bcmo.cmd.iv | tmpBlock

  io.core.cmd.block := isEnc ? (io.bcmo.cmd.block ^ xorValue) | io.bcmo.cmd.block

  io.bcmo.rsp.block := isEnc ? io.core.rsp.block | (io.core.rsp.block ^ xorValue)

  when(io.core.rsp.valid){
    tmpBlock := isEnc ? io.core.rsp.block | io.bcmo.cmd.block
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
case class OFB_Std(config: SymmetricCryptoBlockConfig, chainningMode: EncryptionMode, algoMode: EncryptionMode) extends Component {

  assert(algoMode != ENC_DEC, "This is a cipher chaining, the algo mode must be either in Encryption or decryption")

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = config.keyWidth.value,
      blockWidth = config.blockWidth.value,
      useEncDec  = chainningMode == ENC_DEC,
      ivWidth    = config.blockWidth.value
    )))

    val core = master(SymmetricCryptoBlockIO(config))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT

  if(config.useEncDec) io.core.cmd.enc := Bool(algoMode == ENCRYPT)

  val tmpBlock = Reg(Bits(config.blockWidth))

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.block := (isInit) ? io.bcmo.cmd.iv | tmpBlock
  io.core.cmd.key   := io.bcmo.cmd.key

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := io.core.rsp.block ^ io.bcmo.cmd.block

  when(io.core.rsp.valid){
    tmpBlock := io.core.rsp.block
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
  *                |       |                |---- ...
  *            Ciphertext--/            Ciphertext
  */
case class CFB_Std(config: SymmetricCryptoBlockConfig, chainningMode: EncryptionMode, algoMode: EncryptionMode) extends Component {

  assert(algoMode != ENC_DEC, "This is a cipher chaining, the algo mode must be either in Encryption or decryption")

  val io = new Bundle{
    val bcmo = slave (BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = config.keyWidth.value,
      blockWidth = config.blockWidth.value,
      useEncDec  = chainningMode == ENC_DEC,
      ivWidth    = config.blockWidth.value
    )))

    val core = master(SymmetricCryptoBlockIO(config))
  }

  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT

  if(config.useEncDec) io.core.cmd.enc := Bool(algoMode == ENCRYPT)

  val isEnc = chainningMode match{
    case ENCRYPT =>  True
    case DECRYPT =>  False
    case ENC_DEC =>
      assert(io.core.config.useEncDec, "This core doesn't support encryption/decryption mode")
      io.bcmo.cmd.enc
  }

  val tmpBlock = Reg(Bits(config.blockWidth))
  val cipher   = Bits(config.blockWidth)

  io.core.cmd.valid := io.bcmo.cmd.valid
  io.core.cmd.block := (isInit) ? io.bcmo.cmd.iv | tmpBlock
  io.core.cmd.key   := io.bcmo.cmd.key

  io.bcmo.cmd.ready := io.core.cmd.ready
  io.bcmo.rsp.valid := io.core.rsp.valid
  io.bcmo.rsp.block := cipher

  cipher := io.core.rsp.block ^ io.bcmo.cmd.block

  when(io.core.rsp.valid){
    tmpBlock := (isEnc) ? cipher | io.bcmo.cmd.block
  }
}


///**
//  * Counter (CTR) - Stream cipher
//  *
//  *         (IV ## Counter)     (IV ## Counter + 1)
//  *           ___|____             ___|____
//  *  Key --> |  Algo  |   Key --> |  Algo  |  ...
//  *          |________|           |________|
//  *              |                    |
//  * Plaintext ->XOR      Plaintext ->XOR
//  *              |                    |
//  *          Ciphertext           Ciphertext
//  */
//class CTR_Std(g: SymmetricCryptoBlockGeneric, ivWidth: Int, f_inc: Bits => Bits, f_blockIn: (Bits, Bits) => Bits, initCounter: BigInt, mode: EncryptionMode) extends Component {
//
//  assert(ivWidth > 0 && ivWidth < g.blockWidth.value, "CTR : IV size error")
//
//  val io = new Bundle {
//    val bcmo = slave(BCMO_Std_IO(BCMO_Std_Generic(
//      keyWidth   = g.keyWidth.value,
//      blockWidth = g.blockWidth.value,
//      useEncDec  = mode == ENC_DEC,
//      ivWidth    = ivWidth
//    )))
//
//    val core = master(SymmetricCryptoBlockIO(g))
//  }
//
//  val isInit   = io.bcmo.cmd.valid && io.bcmo.cmd.mode === BCMO_Std_CmdMode.INIT
//
//  assert(g.blockWidth.value - io.bcmo.g.ivWidth > 0)
//  val counter = Reg(Bits((g.blockWidth.value - io.bcmo.g.ivWidth) bits))
//  val counterTmp = cloneOf(counter)
//
//  when(isInit){
//    counterTmp := initCounter
//  }otherwise{
//    counterTmp := f_inc(counter)
//  }
//
//  counter := counterTmp
//
//  io.core.cmd.valid := io.bcmo.cmd.valid
//  io.core.cmd.key   := io.bcmo.cmd.key
//  io.core.cmd.block := f_blockIn(io.bcmo.cmd.iv, counterTmp)
//
//  io.bcmo.cmd.ready := io.core.cmd.ready
//  io.bcmo.rsp.valid := io.core.rsp.valid
//  io.bcmo.rsp.block := io.core.rsp.block ^ io.bcmo.cmd.block
//
//  if(g.useEncDec) io.core.cmd.enc := True
//
//}
//
//object CTR_Std{
//
//  def apply(g: SymmetricCryptoBlockGeneric, mode: EncryptionMode): CTR_Std = {
//    new CTR_Std(
//      g           = g,
//      ivWidth     = g.blockWidth.value / 2,
//      f_inc       = x => (x.asUInt + 1).asBits,
//      f_blockIn   = (iv: Bits, cnt: Bits) => iv ## cnt,
//      initCounter = 0,
//      mode        = mode
//    )
//  }
//}
