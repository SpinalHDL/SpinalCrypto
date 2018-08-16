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
package spinal.crypto.padding

import spinal.core._
import spinal.crypto.hash._
import spinal.lib.fsm._
import spinal.lib._


/**
  * Configuration of the Hash Padding core
  */
case class HashPadding_Config(
  dataInWidth  : BitCount,
  dataOutWidth : BitCount ,
  endianess    : EndiannessMode,
  symbolWidth  : BitCount = 8 bits
) extends PaddingConfig(dataInWidth, dataOutWidth, symbolWidth)


/**
  * Hash Padding
  *
  * The message to hash must be padded as following:
  *    - Add a one bit a the end of the message
  *    - Add a sequence of 0 until to get a block of 448-bits
  *    - Write the size in bits of the message on 64 bits (l0 l1) e.g : 24 bits => 00000018 00000000
  *
  */
class HashPadding_Std(config: HashPadding_Config) extends Component {

  assert(config.dataInWidth.value == 32, "Currently Hash padding supports only 32 bits")

  val io = slave(PaddingIO(config.getPaddingIOConfig))

  val nbrWordInBlock = config.dataOutWidth.value / config.dataInWidth.value
  val nbrByteInWord  = config.dataInWidth.value / 8

  val cntBit     = Reg(UInt(64 bits))
  val block      = Reg(Vec(Bits(config.dataInWidth), nbrWordInBlock))
  val indexWord  = Reg(UInt(log2Up(nbrWordInBlock) bits))

  // default value
  io.rsp.data   := block.asBits
  io.rsp.valid  := False // default value
  io.cmd.ready  := False // default value

  val maskMsg = io.cmd.size.mux(
    U"00"  -> (if(config.endianess == LITTLE_endian) B"x000000FF" else B"xFF000000"),
    U"01"  -> (if(config.endianess == LITTLE_endian) B"x0000FFFF" else B"xFFFF0000"),
    U"10"  -> (if(config.endianess == LITTLE_endian) B"x00FFFFFF" else B"xFFFFFF00"),
    U"11"  ->  B"xFFFFFFFF"
  )

  val maskSet1 = io.cmd.size.mux(
    U"00"  -> (if(config.endianess == LITTLE_endian) B"x00008000" else B"x00800000"),
    U"01"  -> (if(config.endianess == LITTLE_endian) B"x00800000" else B"x00008000"),
    U"10"  -> (if(config.endianess == LITTLE_endian) B"x80000000" else B"x00000080"),
    U"11"  -> B"x00000000"
  )

  /**
    * Padding state machine
    */
  val sm = new StateMachine {

    val addPaddingNextWord = Reg(Bool)
    val isBiggerThan448    = Reg(Bool)
    val fillNewBlock       = Reg(Bool)

    val isLastFullWordInBlock = indexWord === 0 && io.cmd.size === (nbrByteInWord - 1)

    always{
      when(io.init){
        cntBit    := 0
        indexWord := nbrWordInBlock - 1
        block.map(_ := 0)
        goto(sLoad)
      }
    }

    val sLoad: State = new State with EntryPoint{ /* Load the block register of 512-bit */
      whenIsActive{

        addPaddingNextWord := True
        isBiggerThan448    := False
        fillNewBlock       := False

        when(io.cmd.valid){

          block(indexWord) := io.cmd.data

          when(io.cmd.last){

            cntBit := cntBit + io.cmd.size.mux(
              U"00"  ->  8,
              U"01"  -> 16,
              U"10"  -> 24,
              U"11"  -> 32
            )
            when(isLastFullWordInBlock){
              goto(sProcessing)
            }otherwise{
              isBiggerThan448 := indexWord < 2 || (indexWord === 2 && io.cmd.size === (nbrByteInWord - 1))
              goto(sPadding)
            }
          }otherwise{

            cntBit     := cntBit + config.dataInWidth.value
            indexWord  := indexWord - 1

            when(indexWord === 0){
              goto(sProcessing)
            }otherwise{
              io.cmd.ready := True
            }
          }
        }
      }

      val sPadding: State = new State { /* Do padding  */
        onEntry{

          when(isLastFullWordInBlock || fillNewBlock){
            indexWord     := nbrWordInBlock - 1
            fillNewBlock  := False
          }otherwise{
            block(indexWord) := (io.cmd.data & maskMsg) | maskSet1
            when(indexWord =/= 0)  { indexWord := indexWord - 1 }
            when(io.cmd.size =/= (nbrByteInWord - 1)){ addPaddingNextWord := False }
          }
        }

        whenIsActive{

          when(indexWord > 1 || isBiggerThan448){

            indexWord := indexWord - 1

            when(addPaddingNextWord){
              block(indexWord)   := (if(config.endianess == LITTLE_endian) B"x00000080" else B"x80000000")
              addPaddingNextWord := False
            }otherwise{
              when(indexWord =/= 0){
                block(indexWord) := B(0).resized
              }
            }

            when(indexWord === 0){
              fillNewBlock := True
              goto(sProcessing)
            }

          }otherwise{

            if(config.endianess == LITTLE_endian){
              block(1) := cntBit(31 downto 0).asBits
              block(0) := cntBit(63 downto 32).asBits
            }else{
              block(0) := cntBit(31 downto 0).asBits
              block(1) := cntBit(63 downto 32).asBits
            }

            goto(sProcessing)
          }
        }
      }

      val sProcessing: State = new State {    /* Run Hash Engine */
        whenIsActive{
          io.rsp.valid := True

          when(io.rsp.ready){

            block.map(_ := 0)

            when(isBiggerThan448 || isLastFullWordInBlock) {
              isBiggerThan448 := False
              goto(sPadding)
            } otherwise {
              io.cmd.ready := True
              goto(sLoad)
            }
          }
        }
      }
    }
  }
}