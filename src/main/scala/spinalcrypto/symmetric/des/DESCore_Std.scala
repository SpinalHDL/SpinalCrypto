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
package spinalcrypto.symmetric.des

import spinal.core._
import spinal.lib._
import spinalcrypto.symmetric.{SymmetricCryptoCoreGeneric, SymmetricCryptoCoreIO}


/**
  * Contains all constants for the DES Block
  */
object DESCoreSpec{

  def initialPermutation = Seq(
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)

  def finalPermutation   = Seq(
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25)

  def expansion  = List(
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1)

  def fixedPermutation  =   List(
    16,  7 , 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
    2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25)

  def pc_1   =  Seq(
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4)

  def pc_2    =   Seq(
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)

  /* SBox definition  */
  def sBox_1   = List(
    14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7,
    0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8,
    4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0,
    15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13)

  def sBox_2   = List(
    15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9)

  def sBox_3   = List(
    10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12)

  def sBox_4   = List(
    7, 13, 14, 3,  0,  6,  9, 10,  1, 2, 8,  5, 11, 12,  4, 15,
    13,  8, 11, 5,  6, 15,  0,  3,  4, 7, 2, 12,  1, 10, 14,  9,
    10,  6,  9, 0, 12, 11,  7, 13, 15, 1, 3, 14,  5,  2,  8,  4,
    3, 15,  0, 6, 10,  1, 13,  8,  9, 4, 5, 11, 12,  7,  2, 14)

  def sBox_5   = List(
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14, 9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3)

  def sBox_6   = List(
    12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13)

  def sBox_7   = List(
    4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1,
    13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6,
    1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2,
    6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12)

  def sBox_8   = List(
    13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11)

  /* Data width */
  def blockWidth     = 64 bits
  def keyWidth       = 56 bits
  def keyWidthParity =  8 bits

  /** Number of Round used by DES */
  def nbrRound       = 16

  /** Used by the key scheduling */
  def oneShiftRound = List(1,2,9,16)  // 1 left rotation for round 1,2,9,16 and others 2 left shift rotation
}


/**
  * Define some usefull funtion
  */
object DESCore_Std{

  /** Permutation, Compression and expansion
    *  These functions permute a vector thanks to the table (!! The table is given for a software application !!)
    */
  def permutation(table:Seq[Int], vector:Bits): Bits = expansion(table.toList, vector)

  def compression(table:Seq[Int], vector:Bits): Bits = expansion(table.toList,vector)

  def expansion(table:List[Int], vector:Bits): Bits = Cat(table.reverse.map(index => vector(vector.getWidth - index)))
}


/**
  * Data Encryption Standard (DES)
  *
  *                      _________
  *                     |         |
  *    -- Plaintext --->|   DES   |-- Ciphertext -->
  *       (64 bits)     |_________|   (64 bits)
  *                          |
  *                      Key (56 bits)
  *                          |
  *                 Key + parity (64 bits)
  *
  *
  */
class DESCore_Std() extends Component{

  val gIO  = SymmetricCryptoCoreGeneric(keyWidth    = DESCoreSpec.keyWidth + DESCoreSpec.keyWidthParity,
                                         blockWidth  = DESCoreSpec.blockWidth,
                                         useEncDec   = true)

  val io = slave(new SymmetricCryptoCoreIO(gIO))

  val roundNbr    = UInt(log2Up(DESCoreSpec.nbrRound) + 1 bits)
  val lastRound   = io.cmd.enc ? (roundNbr === (DESCoreSpec.nbrRound-2)) | (roundNbr === 2)
  val init        = io.cmd.valid.rise(False)
  val nextRound   = Reg(Bool) init(False) setWhen(init) clearWhen(lastRound)
  val rspValid    = Reg(Bool) init(False) setWhen(lastRound) clearWhen(init)


  /**
    * Count the number of round
    *   - Encryption 0 -> 15
    *   - Decryption 16 -> 1
    */
  val ctnRound = new Area{
    val round = Reg(UInt(log2Up(DESCoreSpec.nbrRound) + 1 bits))

    when(init){
      round := io.cmd.enc ? U(0) | DESCoreSpec.nbrRound
    }

    when(nextRound){
      round := io.cmd.enc ? (round + 1) | (round - 1)
    }
  }

  roundNbr := ctnRound.round


  /**
    * Initial permutation
    */
  val initialBlockPermutation = new Area{
    val perm = DESCore_Std.permutation(DESCoreSpec.initialPermutation, io.cmd.block)
  }


  /**
    * Key scheduling
    *   For encryption :
    *                          Key 64 bits
    *                              |
    *                   -----------------------
    *                  |       Parity drop     |   (remove 8 bits => 56 bits)
    *                   -----------------------
    *                     |                 |       (2 x 28 bits)
    *               ------------     ------------
    *              | Shift left |   | Shift left |  Round key Generator 1
    *               ------------     ------------
    *                  |    |          |      |             !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    *                  |   --------------     |             !!!  Shifting : 1 shift left for round 1,2,9,16,  !!!
    * K1 (48 bits)  <--|--| compression  |    |             !!!    others rounds 2 shift left                 !!!
    *                  |   --------------     |             !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    *                 ...       ....         ...
    *               ------------     ------------
    *              | Shift left |   | Shift left | Round key Generator 16
    *               ------------     ------------
    *                       |          |
    *                      --------------
    * K16 (48bits) <------| compression  |
    *                      --------------
    *
    * For decryption :
    *     Replace the Shift left by a shift right
    */
  val keyScheduling = new Area{

    val shiftKey   = Reg(Bits(DESCoreSpec.keyWidth))

    // parity drop : 64bits -> 56 bits
    when(init){ shiftKey := DESCore_Std.compression(DESCoreSpec.pc_1, io.cmd.key) }

    // rotate the key (left for encryption and right for decryption)(key is divided into two groups of 28 bits)
    val shiftRes   = Bits(DESCoreSpec.keyWidth)

    when(DESCoreSpec.oneShiftRound.map(index => ctnRound.round === (index-1)).reduce(_ || _) ){
      when(io.cmd.enc){
        shiftRes  := shiftKey(55 downto 28).rotateLeft(1) ## shiftKey(27 downto 0).rotateLeft(1)
      }otherwise{
        shiftRes  := shiftKey(55 downto 28).rotateRight(1) ## shiftKey(27 downto 0).rotateRight(1)
      }
    }otherwise{
      when(io.cmd.enc){
        shiftRes  := shiftKey(55 downto 28).rotateLeft(2) ## shiftKey(27 downto 0).rotateLeft(2)
      }otherwise{

        shiftRes  := shiftKey(55 downto 28).rotateRight(2) ## shiftKey(27 downto 0).rotateRight(2)

        when(ctnRound.round === DESCoreSpec.nbrRound){
          shiftRes  := shiftKey
        }
      }
    }

    // update key shift
    when(nextRound){ shiftKey := shiftRes }

    // compression : (56bits -> 48 bits)
    val keyRound = DESCore_Std.compression(DESCoreSpec.pc_2, shiftRes)
  }


  /**
    * DES function
    *            In 32 bits
    *                |
    *       ---------------------
    *      |     Expansion       | (32 -> 48bits)
    *       ---------------------
    *                |
    *               XOR <--------------- Ki (48 bits)
    *                |
    *      ----   ---        ---
    *     | S1 |-| S2 |-...-| S8 | (sBox)
    *      ----   ---        ---
    *                | (32 bits)
    *       ----------------------
    *      |     Permutation      |
    *       ----------------------
    *                |
    *             Out 32 bits
    */
  val funcDES = new Area{

    // list of SBox ROM 1 to 8
    val sBox     = List(Mem(Bits(4 bits), DESCoreSpec.sBox_8.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_7.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_6.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_5.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_4.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_3.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_2.map(B(_, 4 bits))),
                        Mem(Bits(4 bits), DESCoreSpec.sBox_1.map(B(_, 4 bits))))

    val rightRound   = Bits(32 bits) // set in feistelNetwork Area

    // xor the key with the right block expanded(32 bits -> 48 bits)
    val xorRes = keyScheduling.keyRound ^ DESCore_Std.expansion(DESCoreSpec.expansion, rightRound)

    // sBox stage
    val boxRes   = Bits(32 bits)
    for(i <- 0 until sBox.size){
      val addrSBox = xorRes(i*6+6-1 downto i*6)
      boxRes(i*4+4-1 downto i*4) := sBox(i).readAsync( (addrSBox(5) ## addrSBox(0) ## addrSBox(4 downto 1)).asUInt )
    }

    // fixed permutation
    val rResult = DESCore_Std.permutation(DESCoreSpec.fixedPermutation, boxRes)
  }


  /**
    * Feistel network
    *
    *    --------------------------------
    *   |   Li-1        |      Ri-1      |  (2 x 32 bits) (inBlock)
    *    --------------------------------
    *        |                     |
    *       XOR<---(Des function)--|
    *        |          \__________|_______ Ki
    *        |                     |
    *        \       ____________ /
    *         \_____/___________
    *              /            \
    *    --------------------------------
    *   |   Li          |      Ri        | (2 x 32 bits) (outBlock)
    *    --------------------------------
    */
  val feistelNetwork = new Area{

    val inBlock  = Reg(Bits(DESCoreSpec.blockWidth))

    val outBlock = inBlock(31 downto 0) ## (inBlock(63 downto 32) ^ funcDES.rResult)

    when(init){ inBlock := initialBlockPermutation.perm }
    when(nextRound){ inBlock := outBlock }
  }

  funcDES.rightRound  := feistelNetwork.inBlock(31 downto 0)


  /**
    * Final Permutation of the Block
    *    ( swap outBlock in order to have the same feistel network for each round )
    */
  val finalBlockPermutation = new Area{
    val perm = DESCore_Std.permutation(DESCoreSpec.finalPermutation, feistelNetwork.outBlock(31 downto 0) ## feistelNetwork.outBlock(63 downto 32) )
  }


  /*
   * Update the output
   */
  val cmdReady  = RegNext(rspValid.rise())
  io.rsp.block := RegNext(finalBlockPermutation.perm)
  io.rsp.valid := cmdReady

  io.cmd.ready := cmdReady
}