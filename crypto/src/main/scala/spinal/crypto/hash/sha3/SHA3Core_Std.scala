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
package spinal.crypto.hash.sha3

import spinal.core._
import spinal.crypto.construtor.{SpongeCore_Std}
import spinal.crypto.hash.{HashCoreConfig, HashCoreIO}
import spinal.crypto.padding.{Pad_xB_1_Std, Padding_xB_1_Config}
import spinal.crypto.primitive.keccak.KeccakF_Std
import spinal.lib._

/**
  * SHA-3 Core STD
  *
  * @param sha3Type     SHA3 type
  * @param dataWidth    Input data width
  */
class SHA3Core_Std(sha3Type: SHA3_Type, dataWidth: BitCount = 32 bits) extends Component {

  val configCore =  HashCoreConfig(
    dataWidth      = dataWidth,
    hashWidth      = sha3Type.hashWidth bits,
    hashBlockWidth = 0 bits
  )

  /** IO */
  val io = slave(HashCoreIO(configCore))

  val padding = new Pad_xB_1_Std(Padding_xB_1_Config(dataInWidth = dataWidth, dataOutWidth = sha3Type.r bits, pad_xB = 0x06))
  val sponge  = new SpongeCore_Std(capacity = sha3Type.c, rate = sha3Type.r, d = sha3Type.hashComputationWidth)
  val func    = new KeccakF_Std(sha3Type.c + sha3Type.r)


  // io <-> padding
  padding.io.cmd.valid := io.cmd.valid
  padding.io.cmd.data  := io.cmd.msg
  padding.io.cmd.last  := io.cmd.last
  padding.io.cmd.size  := io.cmd.size
  io.cmd.ready         := padding.io.cmd.ready

  padding.io.init      := io.init

  // padding <-> sponge
  sponge.io.cmd.valid  := padding.io.rsp.valid
  sponge.io.cmd.last   := padding.io.rsp.last
  sponge.io.cmd.n      := Cat(padding.io.rsp.data.subdivideIn(64 bits).map(EndiannessSwap(_)))
  padding.io.rsp.ready := sponge.io.cmd.ready

  sponge.io.init       := io.init

  // sponge <-> func
  sponge.io.func <> func.io

  // sponge <-> io
  io.rsp.valid  := padding.io.cmd.ready & sponge.io.cmd.last
  io.rsp.digest := Cat(sponge.io.rsp.z.subdivideIn(64 bits).map(EndiannessSwap(_))).asBits.resizeLeft(sha3Type.hashWidth)
}


