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


/**
  * Symmetric Crypto block generiics
  * @param keyWidth Key width
  * @param blockWidth Block width
  * @param useEncDec Create a signal for the encryption/decryption
  */
case class SymmetricCryptoCoreGeneric(keyWidth    : BitCount,
                                      blockWidth  : BitCount,
                                      useEncDec   : Boolean = true){}


/**
  * Command interface for a symmetric block algo
  */
case class SymmetricCryptoCoreCmd(g: SymmetricCryptoCoreGeneric) extends Bundle {
  val key    = Bits(g.keyWidth)
  val block  = Bits(g.blockWidth)
  val enc    = if(g.useEncDec) Bool else null
}

/**
  * Response interface for a symmetric block algo
  */
case class SymmetricCryptoCoreRsp(g: SymmetricCryptoCoreGeneric) extends Bundle {
  val block = Bits(g.blockWidth)
}


/**
  * Interface used by a symmetric block algo
  */
case class SymmetricCryptoCoreIO(g: SymmetricCryptoCoreGeneric) extends Bundle with IMasterSlave{
  val cmd  = Stream(SymmetricCryptoCoreCmd(g))
  val rsp  = Flow(SymmetricCryptoCoreRsp(g))

  override def asMaster() = {
    master(cmd)
    slave(rsp)
  }
}