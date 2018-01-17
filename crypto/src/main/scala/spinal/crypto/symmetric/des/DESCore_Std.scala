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
package spinal.crypto.symmetric.des

import spinal.core._
import spinal.lib._
import spinal.crypto.symmetric.{SymmetricCryptoBlockGeneric, SymmetricCryptoBlockIO}


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

  val gIO  = SymmetricCryptoBlockGeneric(keyWidth    = DESCoreSpec.keyWidth + DESCoreSpec.keyWidthParity,
                                        blockWidth  = DESCoreSpec.blockWidth,
                                        useEncDec   = true)

  val io = slave(new SymmetricCryptoBlockIO(gIO))

  val roundNbr    = UInt(log2Up(DESCoreSpec.nbrRound) + 1 bits)
  val lastRound   = io.cmd.enc ? (roundNbr === (DESCoreSpec.nbrRound-2)) | (roundNbr === 2)


  /**
    * State machine
    */
  val sm = new Area{

    object DESCoreState extends SpinalEnum{
      val sInit, sProcessing, sRegister, sResult = newElement()
    }

    import DESCoreState._

    val state        = RegInit(sInit)
    val isInit       = False
    val isProcessing = False
    val isResult     = False

    switch(state){
      is(sInit){
        isInit := True
        when(io.cmd.valid){
          state := sProcessing
        }
      }
      is(sProcessing){
        isProcessing := True
        when(lastRound){
          state  := sRegister
        }
      }
      is(sRegister){
        state  := sResult
      }
      default{ // Result
        isResult := True
        state    := sInit
      }
    }

  }

  /**
    * Count the number of round
    *   - Encryption 0 -> 15
    *   - Decryption 16 -> 1
    */
  val ctnRound = new Area{
    val round = Reg(UInt(log2Up(DESCoreSpec.nbrRound) + 1 bits)) init(0)

    when(sm.isInit){
      round := io.cmd.enc ? U(0) | DESCoreSpec.nbrRound
    }

    when(sm.isProcessing){
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
    when(sm.isInit){ shiftKey := DESCore_Std.compression(DESCoreSpec.pc_1, io.cmd.key) }

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
    when(sm.isProcessing){ shiftKey := shiftRes }

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

    when(sm.isInit){ inBlock := initialBlockPermutation.perm }
    when(sm.isProcessing){ inBlock := outBlock }
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
  io.rsp.block := RegNext(finalBlockPermutation.perm)
  io.rsp.valid := sm.isResult

  io.cmd.ready := sm.isResult
}
