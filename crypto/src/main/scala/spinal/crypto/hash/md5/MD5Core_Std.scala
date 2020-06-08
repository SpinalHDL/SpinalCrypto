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
package spinal.crypto.hash.md5

import spinal.core._
import spinal.lib._
import spinal.crypto.hash._
import spinal.crypto.padding.{HashPadding_Config, HashPadding_Std}


/**
  * MD5Core_Std component
  *
  * !!!!! MD5 works in little-Endian !!!!!!!
  *
  * MD5 specification : https://www.ietf.org/rfc/rfc1321.txt
  *
  */
class MD5Core_Std(dataWidth: BitCount = 32 bits) extends Component {

  val configCore =  HashCoreConfig(
    dataWidth      = dataWidth,
    hashWidth      = MD5.hashWidth,
    hashBlockWidth = MD5.blockWidth
  )

  val configPadding = HashPadding_Config(
    dataInWidth  = dataWidth ,
    dataOutWidth = MD5.blockWidth,
    endianess    = LITTLE_endian
  )

  val io = slave(HashCoreIO(configCore))

  val engine  = new MD5Engine_Std()
  val padding = new HashPadding_Std(configPadding)

  // Connect IO <-> padding
  padding.io.init      := io.init
  padding.io.cmd.valid := io.cmd.valid
  padding.io.cmd.data  := io.cmd.msg
  padding.io.cmd.last  := io.cmd.last
  padding.io.cmd.size  := io.cmd.size

  io.cmd.ready := padding.io.cmd.ready

  // Connect padding <-> engine
  engine.io.cmd.valid   := padding.io.rsp.valid
  engine.io.cmd.message := padding.io.rsp.data

  padding.io.rsp.ready := engine.io.cmd.ready

  // Connect Engine <-> io
  io.rsp.valid   := engine.io.rsp.valid && io.cmd.last && io.cmd.ready
  io.rsp.digest  := engine.io.rsp.digest
  engine.io.init := io.init
}


/**
  * The MD5 engine take as input a block message of 512 bits and produce a hash value of 128 bits
  *
  * msgBlock
  *(512 bits)
  *    |     _______ _______ _______ _______
  *    |    |  ivA  |  ivB  |  ivC  |  ivD  |<------\
  *    |     ------- ------- ------- -------  --\   |
  *    |        |       |      |        |       |   |
  *    |        A       B      C        D       |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    |--->|         16 iterations         |   |   |
  *    |     -------------------------------    |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    |--->|         16 iterations         |   |   |
  *    |     -------------------------------    |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    |--->|         16 iterations         |   |   |
  *    |     -------------------------------    |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    \--->|         16 iterations         |   |   |
  *          -------------------------------    |   |
  *             |       |      |        |       |   |
  *             + <---- + <--- + <----- + <-----/   |
  *             |       |      |        |           |
  *          _______________________________        |
  *         |         128 bits Hash         |-------/
  *          -------------------------------
  *
  */
class MD5Engine_Std extends Component {

  val io = slave(HashEngineIO(MD5.blockWidth , MD5.hashWidth))

  val iv    = Vec(Reg(Bits(MD5.subBlockWidth)), 4)

  val memT  = Mem(UInt(32 bits), MD5.constantT.map(U(_, 32 bits)))
  val memK  = Mem(UInt(4 bits),  MD5.indexK.map(U(_, 4 bits)))

  val memS  = List(Mem(UInt(5 bits),  MD5.shiftCstS.slice(0,  4).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5.shiftCstS.slice(4,  8).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5.shiftCstS.slice(8, 12).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5.shiftCstS.slice(12,16).map(U(_, 5 bits)))
  )

  /**
    * Iterative round:
    *
    * X : message block (512 bits)
    * T : constant table (32 bits)
    * A, B, C, D : 32 bits
    *         _______ _______ _______ _______
    *        |   A   |   B   |   C   |   D   |
    *         ------- ------- ------- -------
    *             |     |  \____   |   ___|
    *             |     |      _\__|__/_
    *             + ----------|   Func  | (Func: F, G, H, I)
    *             |     |      ---------
    *    X[k] --> +     |
    *             |     |
    *    T[i] --> +     |
    *             |     |
    *            << S   |     (left rotation)
    *             |     |
    *             + <---/
    *             |
    *             \______
    *                    \
    *            D       |       B       C
    *         ___|___ ___|___ ___|___ ___|___
    *        |   A'  |   B'  |   C'  |   D'  |
    *         ------- ------- ------- -------
    * Note : A=0, B=1, C=2, D=3
    */
  val iterativeRound = new Area {

    val i = Reg(UInt(6 bits))

    val endIteration = i === 63

    /* Register block */
    val block   = Vec(Reg(Bits(MD5.subBlockWidth)), 4)

    /* Block signals */
    val sBlock  = Vec(Bits(MD5.subBlockWidth), 4)

    // mux to select among the three function F, G, H, I
    val selFunc = B(0, 2 bits)
    val funcResult = selFunc.mux(B"00" -> MD5.funcF(block(1), block(2), block(3)),
                                 B"01" -> MD5.funcG(block(1), block(2), block(3)),
                                 B"10" -> MD5.funcH(block(1), block(2), block(3)),
                                 B"11" -> MD5.funcI(block(1), block(2), block(3)))

    // Cut the message block into 32 bits
    val k = memK(i)
    val wordBlock = io.cmd.message.subdivideIn(32 bits).reverse(k)

    // Select among the 4 memShift memory
    val shiftValue = selFunc.muxList(for(index <- 0 until 4) yield (index, memS(index)(i(1 downto 0)) ))

    // Compute the new value of the B block
    val newBlockB = (funcResult.asUInt + block(0).asUInt + wordBlock.asUInt + memT(i)).rotateLeft(shiftValue) + block(1).asUInt


    // last round => add the initial vector to the current block
    when(endIteration){
      sBlock(0) := (block(3).asUInt + iv(0).asUInt).asBits
      sBlock(1) := (newBlockB       + iv(1).asUInt).asBits
      sBlock(2) := (block(1).asUInt + iv(2).asUInt).asBits
      sBlock(3) := (block(2).asUInt + iv(3).asUInt).asBits
    }otherwise{
      // Update the new value of block A, B, C, D
      sBlock  := Vec(block(3), newBlockB.asBits, block(1), block(2))
    }

    // Register signal block
    when(io.cmd.valid){
      block := sBlock
    }
  }


  /**
    * MD5 controller
    */
  val ctrlMD5 = new Area {

    val isProcessing = Reg(Bool)

    when(io.init){
      iterativeRound.block  := MD5.initBlock
      iterativeRound.i      := 0
      isProcessing          := False
    }.elsewhen(io.cmd.valid && !isProcessing && !io.cmd.ready){
      isProcessing := True
      iv := iterativeRound.block
      iterativeRound.i := iterativeRound.i + 1
    }

    when(isProcessing & !io.init){

      // round incrementation
      iterativeRound.i := iterativeRound.i + 1

       /*
        * iterativeRound.i < 16 => selFunc = "00"
        * iterativeRound.i < 32 => selFunc = "01"
        * iterativeRound.i < 48 => selFunc = "10"
        * iterativeRound.i < 64 => selFunc = "11"
        */
      iterativeRound.selFunc := B(iterativeRound.i(5 downto 4))

      when(iterativeRound.endIteration){
        isProcessing := False
      }
    }
  }

  /*
   * Drive the output signals
   */
  io.rsp.digest := Cat(iterativeRound.sBlock.reverse)
  io.rsp.valid  := iterativeRound.endIteration
  io.cmd.ready  := iterativeRound.endIteration
}