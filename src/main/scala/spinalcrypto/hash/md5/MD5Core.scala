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
package spinalcrypto.hash.md5

import spinal.core._
import spinal.lib._

import scala.math.{pow, sin}


/**
  * MD5 core command
  */
case class MD5CoreCmd() extends Bundle{
  val block = Bits(MD5CoreSpec.msgBlockSize)
}

/**
  * MD5 core response
  */
case class MD5CoreRsp() extends Bundle{
  val digest = Bits(MD5CoreSpec.digestSize)
}


/**
  * MD5 Specification
  */
object MD5CoreSpec{

  /** Size of a message block */
  def msgBlockSize  = 512 bits
  /** Size of the A B C D block */
  def subBlockSize  =  32 bits
  /** Digest message */
  def digestSize    = 128 bits
  /** Total number of iterations */
  def nbrIteration  = 4*16

  def initBlockA = B"x67452301"
  def initBlockB = B"xEFCDAB89"
  def initBlockC = B"x98BADCFE"
  def initBlockD = B"x10325476"

  def funcF(b: Bits, c: Bits, d: Bits): Bits = (b & c) | (~b & d)
  def funcG(b: Bits, c: Bits, d: Bits): Bits = (b & d) | (~d & c)
  def funcH(b: Bits, c: Bits, d: Bits): Bits = b ^ c ^ d
  def funcI(b: Bits, c: Bits, d: Bits): Bits = c ^ (b | ~d)


  /** T[i] := floor(2^32 × abs(sin(i + 1))) */
  def constantT: List[BigInt] = for(i <- List.range(0,64)) yield BigDecimal((pow(2,32) * sin(i + 1.0).abs)).toBigInt()

  /**
    * ShiftValue is used to know how much left rotation must be done
    * Original array :
    *   7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    *   5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    *   4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    *   6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21)
    */
  def shiftCstS: List[Int] = List(7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21)


  /**
    * Index K is used to select a word in the 512-bit of the message block
    *  0 .. 15 : index = i
    * 16 .. 31 : index = 5 * i + 1 mod 16
    * 32 .. 47 : index = 3 * i + 5 mod 16
    * 63 .. 34 : index = 7 * i mod 16
    */
  def indexK: List[Int] = for(i <- List.range(0, 64)) yield if      (i < 16) i
                                                            else if (i < 32) (5 * i + 1) % 16
                                                            else if (i < 48) (3 * i + 5) % 16
                                                            else             (7 * i) % 16
}


/**
  * The MD5 algorithm is a hash function producing a 128-bit hash value. MD5 works with block of 512-bit. The message to
  * hash must be padded as following:
  *    - Add a one bit a the end of the message
  *    - Add a sequence of 0 until to get a block of 448-bits
  *    - Write the size in bits of the message on 64 bits (l0 l1) e.g : 24 bits => 00000018 00000000
  *
  * !!!!! MD5 works in little-Endian !!!!!!!
  *
  * doc : https://www.ietf.org/rfc/rfc1321.txt
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
class MD5Core extends Component{

  val io = new Bundle{
    val init = in Bool
    val cmd  = slave Stream(MD5CoreCmd())
    val rsp  = master Flow(MD5CoreRsp())
  }

  val ivA   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val ivB   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val ivC   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val ivD   = Reg(Bits(MD5CoreSpec.subBlockSize))

  val memT  = Mem(UInt(32 bits), MD5CoreSpec.constantT.map(U(_, 32 bits)))
  val memK  = Mem(UInt(4 bits),  MD5CoreSpec.indexK.map(U(_, 4 bits)))

  val memS  = List(Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(0,  4).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(4,  8).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(8, 12).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(12,16).map(U(_, 5 bits))))

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
    */
  val iterativeRound = new Area{

    val i = Reg(UInt(6 bits))

    val endIteration = i === 63

    /* Register block */
    val blockA   = Reg(Bits(MD5CoreSpec.subBlockSize))
    val blockB   = Reg(Bits(MD5CoreSpec.subBlockSize))
    val blockC   = Reg(Bits(MD5CoreSpec.subBlockSize))
    val blockD   = Reg(Bits(MD5CoreSpec.subBlockSize))

    /* Block signals */
    val sblockA = B(0, MD5CoreSpec.subBlockSize)
    val sblockB = B(0, MD5CoreSpec.subBlockSize)
    val sblockC = B(0, MD5CoreSpec.subBlockSize)
    val sblockD = B(0, MD5CoreSpec.subBlockSize)

    // mux to select among the three function F, G, H, I
    val selFunc = B(0, 2 bits)
    val funcResult = selFunc.mux(B"00" -> MD5CoreSpec.funcF(blockB, blockC, blockD),
                                 B"01" -> MD5CoreSpec.funcG(blockB, blockC, blockD),
                                 B"10" -> MD5CoreSpec.funcH(blockB, blockC, blockD),
                                 B"11" -> MD5CoreSpec.funcI(blockB, blockC, blockD))

    // Cut the message block into 32 bits
    val k = memK(i)
    val wordBlock = k.muxList(for(index <- 0 until 16) yield (15-index, io.cmd.block(index*32+32-1 downto index*32)))

    // Select among the 4 memShift memory
    val shiftValue = selFunc.muxList(for(index <- 0 until 4) yield (index, memS(index)(i(1 downto 0)) ))

    // Compute the new value of the B block
    val newBlockB = (funcResult.asUInt + blockA.asUInt + wordBlock.asUInt + memT(i)).rotateLeft(shiftValue) + blockB.asUInt


    // Update the new value of block A, B, C, D
    sblockA := blockD
    sblockB := newBlockB.asBits
    sblockC := blockB
    sblockD := blockC

    // last round => add the initial vector to the current block
    when(endIteration){
      sblockA := (blockD.asUInt + ivA.asUInt).asBits
      sblockB := (newBlockB     + ivB.asUInt).asBits
      sblockC := (blockB.asUInt + ivC.asUInt).asBits
      sblockD := (blockC.asUInt + ivD.asUInt).asBits
    }

    // Register signal block
    when(io.cmd.valid){
      blockA  := sblockA
      blockB  := sblockB
      blockC  := sblockC
      blockD  := sblockD
    }
  }


  /**
    * MD5 controller
    */
  val ctrlMD5 = new Area {

    val isProcessing = Reg(Bool) init(False)

    when(io.init){
      iterativeRound.blockA := MD5CoreSpec.initBlockA
      iterativeRound.blockB := MD5CoreSpec.initBlockB
      iterativeRound.blockC := MD5CoreSpec.initBlockC
      iterativeRound.blockD := MD5CoreSpec.initBlockD
      iterativeRound.i := 0
      isProcessing     := False
    }.elsewhen(io.cmd.valid && !isProcessing && !io.cmd.ready){
      isProcessing := True
      ivA := iterativeRound.blockA
      ivB := iterativeRound.blockB
      ivC := iterativeRound.blockC
      ivD := iterativeRound.blockD
      iterativeRound.i := iterativeRound.i + 1
    }

    when(isProcessing){

      iterativeRound.i := iterativeRound.i + 1

      when(iterativeRound.i < 16){
        iterativeRound.selFunc := B"00"
      }.elsewhen(iterativeRound.i < 32){
        iterativeRound.selFunc := B"01"
      }.elsewhen(iterativeRound.i < 48){
        iterativeRound.selFunc := B"10"
      }.otherwise{
        iterativeRound.selFunc := B"11"
      }

      when(iterativeRound.endIteration){
        isProcessing := False
      }
    }
  }

  /*
   * Drive the output signals
   */
  io.rsp.digest := iterativeRound.sblockA ## iterativeRound.sblockB ## iterativeRound.sblockC ## iterativeRound.sblockD
  io.rsp.valid  := iterativeRound.endIteration
  io.cmd.ready  := iterativeRound.endIteration
}