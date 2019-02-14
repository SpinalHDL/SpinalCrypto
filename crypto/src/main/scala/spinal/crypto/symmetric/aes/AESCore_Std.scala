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
package spinal.crypto.symmetric.aes

import spinal.core._
import spinal.lib._
import spinal.lib.fsm.{EntryPoint, State, StateMachine}

import spinal.crypto.symmetric.{SymmetricCryptoBlockConfig, SymmetricCryptoBlockIO}
import spinal.crypto.devtype._
import spinal.crypto._


/**
  * Advanced Encryption Standard (AES)
  *
  * This design works in encrypt and decrypt and use a key of 128, 192 or 256-bit.
  *
  */
class AESCore_Std(keyWidth: BitCount) extends Component {

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth   = keyWidth,
    blockWidth = AES.blockWidth,
    useEncDec  = true
  )

  val io = slave(SymmetricCryptoBlockIO(gIO))

  val engine      = new AESEngine_Std(keyWidth)
  val keySchedule = new AESKeyScheduleCore_Std(keyWidth)

  engine.io.engine      <> io
  engine.io.keySchedule <> keySchedule.io
}


/**
  * AES engine
  *
  * Encryption :
  *              PlaintText
  *                   |
  *           | Key addition  <---------- k0
  *                   |
  *           | Byte substitution
  *   round   | Shift row
  *     n     | MixColumn
  *           | Key addition  <---------- kn
  *                   |
  *           | Byte substitution
  *   last    | Shift row
  *   round   | Key addition  <---------- klast
  *                   |
  *               CipherText
  *
  *
  * Decryption :
  *               CipherText
  *                   |
  *            | Key addition  <---------- klast
  *    round   | Inv shift row
  *      0     | Inv byte substitution
  *                   |
  *            | Key addition  <---------- kn
  *    round   | Inv mixColumn
  *      n     | Inv shif row
  *            | Inv byte substitution
  *                   |
  *            | Key addition  <---------- k0
  *                   |
  *               Plaintext
  *
  */
class AESEngine_Std(keyWidth: BitCount) extends Component {

  assert(List(128, 192, 256).contains(keyWidth.value), "AES support only 128/192/256 keys width")

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth   = keyWidth,
    blockWidth = AES.blockWidth,
    useEncDec  = true
  )

  val io = new Bundle{
    val engine      = slave(SymmetricCryptoBlockIO(gIO))
    val keySchedule = master(AESKeyScheduleIO_Std(keyWidth))
  }

  // SBox memory for the the byte substitution
  val sBoxMem    = Mem(Bits(8 bits), AES.sBox.map(B(_, 8 bits)))
  val sBoxMemInv = Mem(Bits(8 bits), AES.sBoxInverse.map(B(_, 8 bits)))

  // data state of 128-bit
  val dataState  = Reg(Vec(Bits(8 bits), 16))

  // Count the number of round
  val nbrRound   = AES.nbrRound(keyWidth)
  val cntRound   = Reg(UInt(log2Up(nbrRound) bits))

  /* Key scheduling default value */
  val keyValid    = RegInit(False) clearWhen(io.keySchedule.cmd.ready)
  val keyMode     = RegInit(AESKeyScheduleCmdMode_Std.INIT)
  io.keySchedule.cmd.valid   := keyValid
  io.keySchedule.cmd.round   := (cntRound + 1).resized
  io.keySchedule.cmd.key     := io.engine.cmd.key
  io.keySchedule.cmd.mode    := keyMode

  /* Output default value */
  val smDone           = False
  io.engine.cmd.ready := RegNext(smDone) init(False)
  io.engine.rsp.valid := io.engine.cmd.ready
  io.engine.rsp.block := dataState.reverse.asBits

  /* Sudivide the data and the key into 8 bits */
  val blockByte = io.engine.cmd.block.subdivideIn(8 bits).reverse
  val keyByte   = io.keySchedule.key_i.subdivideIn(8 bits).reverse


  /**
    * Main state machine
    */
  val sm = new StateMachine {

    val keyAddition_cmd = False       // command for the key addtion operation

    val byteSub_cmd = Stream(NoData)  // Command for the byteSubstitution operation
    byteSub_cmd.valid := False

    val shiftRow_cmd = False         // Command for the shift row operation

    val mixCol_cmd = Stream(NoData)  // Command for the mixColumn operation
    mixCol_cmd.valid := False

    val sIdle: State = new State with EntryPoint{
      whenIsActive{
        when(io.engine.cmd.valid && !io.engine.cmd.ready && !keyValid){
          cntRound := io.engine.cmd.enc ? U(0) | U(nbrRound)
          keyValid := True
          keyMode  := AESKeyScheduleCmdMode_Std.INIT
        }

        when(io.keySchedule.cmd.ready){
          keyValid := False
          goto(sKeyAdd)
        }
      }
    }

    val sKeyAdd: State = new State {
      whenIsActive{
        when(!keyValid) {
          keyAddition_cmd := True
          when(io.engine.cmd.enc) { // Encryption
            
            when(cntRound === nbrRound) {
              smDone := True
              goto(sIdle)
            } otherwise {         // not update the key in the last round
              keyValid := True
              keyMode  := AESKeyScheduleCmdMode_Std.NEXT
              goto(sByteSub)
            }

          } otherwise {     // Decryption
            cntRound := cntRound - 1

            when(cntRound =/= 0x00){ // not update the key in the last round
              keyValid := True
              keyMode  := AESKeyScheduleCmdMode_Std.NEXT
            }

            when(cntRound === nbrRound) { // First round don't do the mixColumn
              goto(sShiftRow)
            }.elsewhen(cntRound === 0) {
              smDone := True
              goto(sIdle)
            } otherwise {
              goto(sMixColumn)
            }
          }
        }
      }
    }

    val sByteSub: State = new State {
      whenIsActive{
        byteSub_cmd.valid := True
        when(byteSub_cmd.ready){
          when(io.engine.cmd.enc){ // Encryption
            cntRound := cntRound + 1
            goto(sShiftRow)
          }otherwise{      // Decryption
            goto(sKeyAdd)
          }
        }
      }
    }

    val sShiftRow: State = new State {
      whenIsActive{
        shiftRow_cmd := True
        when(io.engine.cmd.enc){ // Encryption
          when(cntRound === nbrRound){ // Last round don't do the mixColumn
            goto(sKeyAdd)
          }otherwise{
            goto(sMixColumn)
          }
        }otherwise{ // Decryption
          goto(sByteSub)
        }
      }
    }

    val sMixColumn: State = new State {
      whenIsActive{
        mixCol_cmd.valid := True
        when(mixCol_cmd.ready){
          when(io.engine.cmd.enc){ // Encryption
            goto(sKeyAdd)
          }otherwise{      // Decryption
            goto(sShiftRow)
          }
        }
      }
    }
  }


  /**
    * Key Addition operation (1 clock)
    * newState = currentState XOR key
    */
  val keyAddition = new Area {

    when(sm.keyAddition_cmd){
      when((cntRound === 0 && io.engine.cmd.enc) || (cntRound === (nbrRound) && !io.engine.cmd.enc) ){
        for(i <- 0 until dataState.length){
          dataState(i) := blockByte(i) ^ keyByte(i)
        }
      }otherwise{
        for(i <- 0 until dataState.length){
          dataState(i) := dataState(i) ^ keyByte(i)
        }
      }
    }
  }


  /**
    * Byte substitution operation (16 clock)
    * 16 identical SBOX
    * newState(i) = SBox(currentState(i))
    */
  val byteSubstitution = new Area {

    val cntByte = Counter(16)
    sm.byteSub_cmd.ready := cntByte.willOverflowIfInc

    when(sm.byteSub_cmd.valid) {
      cntByte.increment()

      when(io.engine.cmd.enc){
        dataState(cntByte) := sBoxMem(dataState(cntByte).asUInt)
      }otherwise{
        dataState(cntByte) := sBoxMemInv(dataState(cntByte).asUInt)
      }
    }.otherwise{
      cntByte.clear()
    }
  }


  /**
    * Shift row operation (1 clock)
    * newState(i) = ShiftRow(currentState(i))
    */
  val shiftRow = new Area {
    when(sm.shiftRow_cmd) {
      when(io.engine.cmd.enc){
        for ((src, dst) <- AES.shiftRowIndex.zipWithIndex){
          dataState(dst) := dataState(src)
        }
      }otherwise{
        for ((src, dst) <- AES.invShiftRowIndex.zipWithIndex){
          dataState(dst) := dataState(src)
        }
      }
    }
  }


  /**
    * Mix Column operation (4 clock) (Galois field multiplication)
    *
    * newState(i) = MixColumn(currentState(i))
    *
    * Encryption :
    *
    *   C0 = 02 * B0 XOR 03 * B1 XOR 01 * B2 XOR 01 * B3
    *   C1 = 01 * B0 XOR 02 * B1 XOR 03 * B2 XOR 01 * B3
    *   C2 = 01 * B0 XOR 01 * B1 XOR 02 * B2 XOR 03 * B3
    *   C3 = 03 * B0 XOR 01 * B1 XOR 01 * B2 XOR 02 * B3
    *
    * Decryption :
    *
    *   C0 = 0E * B0 XOR 0B * B1 XOR 0D * B2 XOR 09 * B3
    *   C1 = 09 * B0 XOR 0E * B1 XOR 0B * B2 XOR 0D * B3
    *   C2 = 0D * B0 XOR 09 * B1 XOR 0E * B2 XOR 0B * B3
    *   C3 = 0B * B0 XOR 0D * B1 XOR 09 * B2 XOR 0E * B3
    */
  val mixColumn = new Area {

    implicit val polyGF8 = p"x^8+x^4+x^3+x+1"

    val cntColumn = Reg(UInt(log2Up(16) bits))
    sm.mixCol_cmd.ready := cntColumn === 3*4

    when(sm.mixCol_cmd.valid){

      when(io.engine.cmd.enc){ // Encryption
        dataState(0 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x02 ^ GF8(dataState(1 + cntColumn)) * 0x03 ^ GF8(dataState(2 + cntColumn)) * 0x01 ^ GF8(dataState(3 + cntColumn)) * 0x01).toBits()
        dataState(1 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x01 ^ GF8(dataState(1 + cntColumn)) * 0x02 ^ GF8(dataState(2 + cntColumn)) * 0x03 ^ GF8(dataState(3 + cntColumn)) * 0x01).toBits()
        dataState(2 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x01 ^ GF8(dataState(1 + cntColumn)) * 0x01 ^ GF8(dataState(2 + cntColumn)) * 0x02 ^ GF8(dataState(3 + cntColumn)) * 0x03).toBits()
        dataState(3 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x03 ^ GF8(dataState(1 + cntColumn)) * 0x01 ^ GF8(dataState(2 + cntColumn)) * 0x01 ^ GF8(dataState(3 + cntColumn)) * 0x02).toBits()
      }otherwise{       // Decryption
        dataState(0 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x0E ^ GF8(dataState(1 + cntColumn)) * 0x0B ^ GF8(dataState(2 + cntColumn)) * 0x0D ^ GF8(dataState(3 + cntColumn)) * 0x09).toBits()
        dataState(1 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x09 ^ GF8(dataState(1 + cntColumn)) * 0x0E ^ GF8(dataState(2 + cntColumn)) * 0x0B ^ GF8(dataState(3 + cntColumn)) * 0x0D).toBits()
        dataState(2 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x0D ^ GF8(dataState(1 + cntColumn)) * 0x09 ^ GF8(dataState(2 + cntColumn)) * 0x0E ^ GF8(dataState(3 + cntColumn)) * 0x0B).toBits()
        dataState(3 + cntColumn) := (GF8(dataState(0 + cntColumn)) * 0x0B ^ GF8(dataState(1 + cntColumn)) * 0x0D ^ GF8(dataState(2 + cntColumn)) * 0x09 ^ GF8(dataState(3 + cntColumn)) * 0x0E).toBits()
      }

      cntColumn := cntColumn + 4

    }otherwise{
      cntColumn := 0
    }
  }
}
