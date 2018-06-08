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


/**
  * Key Schedule command mode
  *
  * INIT : Init the KeySchedule and get the first key
  * NEXT : Generate the next key
  */
object AESKeyScheduleCmdMode_Std extends SpinalEnum {
  val INIT, NEXT = newElement()
}


/**
  * Key Schedule command
  */
case class AESKeyScheduleCmd_Std(keyWidth: BitCount) extends Bundle {
  val mode  = AESKeyScheduleCmdMode_Std()
  val round = UInt(log2Up(AES.nbrRound(keyWidth)) bits)
  val key   = Bits(keyWidth)
}


/**
  * Key Schedule IO
  */
case class AESKeyScheduleIO_Std(keyWidth: BitCount) extends Bundle with IMasterSlave {
  val cmd    = Stream(AESKeyScheduleCmd_Std(keyWidth))
  val key_i  = Bits(128 bits)

  override def asMaster(): Unit = {
    master(cmd)
    in(key_i)
  }
}


/**
  * Base class for the Key Scheduling
  *
  * Key scheduling pattern http://www.samiam.org/key-schedule.html
  */
class AESKeyScheduleCore_Std(keyWidth: BitCount) extends Component {

  val io = slave(AESKeyScheduleIO_Std(keyWidth))

  // store the current state of the key
  val stateKey     = Reg(Vec(Bits(32 bits), keyWidth.value / 32))
  val stateKey_tmp = Vec(Bits(32 bits),     keyWidth.value / 32)

  // Count internally the number of round
  val cntRound = Reg(UInt(log2Up(AES.nbrRound(keyWidth)) bits))

  // Memory for the RCON and SBOX
  val rconMem = Mem(Bits(8 bits), AES.rcon(keyWidth).map(B(_, 8 bits)))
  val sBoxMem = Mem(Bits(8 bits), AES.sBox.map(B(_, 8 bits)))

  // subdivide the input key in 32-bit
  val keyWord = io.cmd.key.subdivideIn(32 bits).reverse

  // Active the autoupdate of the key (use in decrypt mode)
  val autoUpdate = RegInit(False)

  // cmd ready register
  val cmdready  = RegInit(False)
  io.cmd.ready := cmdready

  // generate a pulse on the cmd.ready
  when(cmdready){ cmdready := False }


  // used by 192-bit and 256-bit key width
  val cntStage = Reg(UInt(4 bits))

  // used by the 192-bit key
  val selKey   = Reg(UInt(2 bits))


  /** Drive key_i */
  keyWidth.value match {
    case 128 =>
      io.key_i := stateKey.reverse.asBits()
    case 192 =>
      io.key_i := selKey.mux(
        0  -> stateKey.reverse.asBits()(191 downto 64),
        1  -> stateKey.reverse.asBits()( 63 downto  0) ## stateKey.reverse.asBits()(191 downto 128),
        2  -> stateKey.reverse.asBits()(127 downto  0),
        3  -> B(0, 128 bits)
      )
    case 256 =>
      io.key_i := cntRound(0).mux(
        False -> stateKey.reverse.asBits()(127 downto 0),
        True  -> stateKey.reverse.asBits()(255 downto 128)
      )
  }

  /** Init command  */
  val initKey = new Area {
    when(io.cmd.valid && io.cmd.mode === AESKeyScheduleCmdMode_Std.INIT && !cmdready && !autoUpdate){

      // initialize the statekey
      for(i <- 0 until stateKey.length)  stateKey(i) := keyWord(i)

      when(io.cmd.round === AES.nbrRound(keyWidth) + 1){ // init cmd with round == (nbrRound+1) => decrypt mode
        autoUpdate := True
        cntRound   := 1
      }otherwise {               // encrypt mode
        cmdready   := True
        cntRound   := 1
      }

      cntStage := 1
      selKey   := 0
    }
  }


  /** Compute the next state of the key */
  val newKey = new Area {

    keyWidth.value match {
      case 128 =>
        stateKey_tmp(0) := stateKey(0)     ^ gFunc(rconMem(cntRound), stateKey(3))
        stateKey_tmp(1) := stateKey_tmp(0) ^ stateKey(1)
        stateKey_tmp(2) := stateKey_tmp(1) ^ stateKey(2)
        stateKey_tmp(3) := stateKey_tmp(2) ^ stateKey(3)

      case 192 =>
        // spinal doesn't do condition analyse for combinatorial loop => must add a tag to avoid error
        stateKey_tmp.foreach(_ := 0)

        when(selKey === 0){
          stateKey_tmp(0) := stateKey(0) ^ gFunc(rconMem(cntStage), stateKey(5))
          stateKey_tmp(1) := stateKey(1) ^ stateKey_tmp(0)
          stateKey_tmp(2) := stateKey(2) ^ stateKey_tmp(1)
          stateKey_tmp(3) := stateKey(3) ^ stateKey_tmp(2)
        }.elsewhen(selKey === 1){
          stateKey_tmp(4) := stateKey(3) ^ stateKey(4)
          stateKey_tmp(5) := stateKey(5) ^ stateKey_tmp(4)
          stateKey_tmp(0) := stateKey(0) ^ gFunc(rconMem(cntStage), stateKey_tmp(5)).addTag(noCombinatorialLoopCheck)
          stateKey_tmp(1) := stateKey(1) ^ stateKey_tmp(0)
        }.elsewhen(selKey === 2){
          stateKey_tmp(2) := stateKey(2) ^ stateKey(1)
          stateKey_tmp(3) := stateKey(3) ^ stateKey_tmp(2)
          stateKey_tmp(4) := stateKey(4) ^ stateKey_tmp(3)
          stateKey_tmp(5) := stateKey(5) ^ stateKey_tmp(4)
        }

      case 256 =>
        stateKey_tmp.foreach(_ := 0)

        when(cntRound(0) === True){
          stateKey_tmp(0) := stateKey(0) ^ gFunc(rconMem(cntStage), stateKey(7))
          stateKey_tmp(1) := stateKey(1) ^ stateKey_tmp(0)
          stateKey_tmp(2) := stateKey(2) ^ stateKey_tmp(1)
          stateKey_tmp(3) := stateKey(3) ^ stateKey_tmp(2)
        }otherwise{
          stateKey_tmp(4) := stateKey(4) ^ hFunc(stateKey(3))
          stateKey_tmp(5) := stateKey(5) ^ stateKey_tmp(4)
          stateKey_tmp(6) := stateKey(6) ^ stateKey_tmp(5)
          stateKey_tmp(7) := stateKey(7) ^ stateKey_tmp(6)
        }
    }
  }


  /** Update Cmd + autoUpdate */
  val updateKey = new Area {

    val storeKey = False

    // Update cmd
    when((io.cmd.valid && io.cmd.mode === AESKeyScheduleCmdMode_Std.NEXT && !cmdready) && !autoUpdate && !cmdready){

      when(cntRound === io.cmd.round){ //  encrypt mode => update the next key
        cmdready   := True
        autoUpdate := False
        storeKey   := True
        cntRound   := cntRound + 1
        selKey     := selKey + 1

      }otherwise{  // decrypt mode => initialize the stateKey and set autoUpdate

        when(io.cmd.round === 1){
          cmdready   := True
        }otherwise{
          autoUpdate := True
        }
        cntRound := 1
        cntStage := 1
        selKey   := 0
        (stateKey, keyWord).zipped.map(_ := _)
      }
    }

    /* update automatically the key until cntRound == io.cmd.round */
    when(autoUpdate){
      storeKey := True
      cntRound := cntRound + 1
      selKey   := selKey + 1

      when(cntRound === io.cmd.round-1){
        cmdready   := True
        autoUpdate := False
      }
    }

    /* Register the current computed key */
    when(storeKey){

      when(selKey === 2){
        selKey := 0
      }

      keyWidth.value match {
        case 128 =>
          stateKey := stateKey_tmp
        case 192 =>
          switch(selKey){
            is(0){
              stateKey(0) := stateKey_tmp(0)
              stateKey(1) := stateKey_tmp(1)
              stateKey(2) := stateKey_tmp(2)
              stateKey(3) := stateKey_tmp(3)
              cntStage    := cntStage + 1
            }
            is(1){
              stateKey(4) := stateKey_tmp(4)
              stateKey(5) := stateKey_tmp(5)
              stateKey(0) := stateKey_tmp(0)
              stateKey(1) := stateKey_tmp(1)
              cntStage    := cntStage + 1
            }
            is(2){
              stateKey(2) := stateKey_tmp(2)
              stateKey(3) := stateKey_tmp(3)
              stateKey(4) := stateKey_tmp(4)
              stateKey(5) := stateKey_tmp(5)
            }
          }
        case 256 =>
          when(cntRound(0) === True){
            stateKey(0) := stateKey_tmp(0)
            stateKey(1) := stateKey_tmp(1)
            stateKey(2) := stateKey_tmp(2)
            stateKey(3) := stateKey_tmp(3)
          }otherwise{
            stateKey(4) := stateKey_tmp(4)
            stateKey(5) := stateKey_tmp(5)
            stateKey(6) := stateKey_tmp(6)
            stateKey(7) := stateKey_tmp(7)
            cntStage    := cntStage + 1
          }
      }
    }
  }


  /** G function */
  def gFunc(rc: Bits, word: Bits): Bits = {
    val result = Bits(32 bits)

    result(31 downto 24) := sBoxMem(word(23 downto 16).asUInt) ^ rc
    result(23 downto 16) := sBoxMem(word(15 downto  8).asUInt)
    result(15 downto  8) := sBoxMem(word( 7 downto  0).asUInt)
    result( 7 downto  0) := sBoxMem(word(31 downto 24).asUInt)

    return result
  }

  /** H function */
  def hFunc(word: Bits): Bits = {
    val result = Bits(32 bits)

    result( 7 downto  0) := sBoxMem(word( 7 downto  0).asUInt)
    result(15 downto  8) := sBoxMem(word(15 downto  8).asUInt)
    result(23 downto 16) := sBoxMem(word(23 downto 16).asUInt)
    result(31 downto 24) := sBoxMem(word(31 downto 24).asUInt)

    return result
  }
}