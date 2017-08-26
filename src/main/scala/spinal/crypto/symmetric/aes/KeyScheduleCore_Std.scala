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
package spinal.crypto.symmetric.aes

import spinal.core._
import spinal.lib._


/**
  * Key Schedule command mode
  *
  * INIT : Init the KeySchedule and get the first key
  * NEXT : Generate the next key
  */
object KeyScheduleCmdMode extends SpinalEnum{
  val INIT, NEXT = newElement()
}

/**
  * Key Schedule command
  */
case class KeyScheduleCmd(keyWidth: BitCount) extends Bundle{
  val mode  = KeyScheduleCmdMode()
  val round = UInt(log2Up(AESCoreSpec.nbrRound(keyWidth)) bits)
  val key   = Bits(keyWidth)
}


/**
  * Key Schedule IO
  */
case class KeyScheduleIO_Std(keyWidth: BitCount) extends Bundle{
  val cmd    = slave(Stream(KeyScheduleCmd(keyWidth)))
  val key_i  = out Bits(128 bits)
}


/**
  * Base class for the Key Scheduling
  *
  * Key scheduling pattern http://www.samiam.org/key-schedule.html
  */
abstract class KeyScheduleCore_Std(keyWidth: BitCount) extends Component{

  val io = KeyScheduleIO_Std(keyWidth)

  // store the current state of the key
  val stateKey     = Reg(Vec(Bits(32 bits), keyWidth.value/32))
  val stateKey_tmp = Vec(Bits(32 bits),     keyWidth.value/32)

  // Count internally the number of round
  val cntRound = Reg(UInt(log2Up(AESCoreSpec.nbrRound(keyWidth)) bits))

  // Memory for the RCON and SBOX
  val rconMem = Mem(Bits(8 bits), AESCoreSpec.rcon(keyWidth).map(B(_, 8 bits)))
  val sBoxMem = Mem(Bits(8 bits), AESCoreSpec.sBox.map(B(_, 8 bits)))

  // subdivide the input key in 32-bit
  val keyWord = io.cmd.key.subdivideIn(32 bits).reverse

  // Active the autoupdate of the key (use in decrypt mode)
  val autoUpdate = RegInit(False)

  // cmd ready register
  val cmdready    = RegInit(False)
  io.cmd.ready    := cmdready


  // generate a pulse on the cmd.ready
  when(cmdready){ cmdready := False }

  /* G function */
  def gFunc(rc: Bits, word: Bits): Bits = {
    val result = Bits(32 bits)

    result(31 downto 24) := sBoxMem(word(23 downto 16).asUInt) ^ rc
    result(23 downto 16) := sBoxMem(word(15 downto  8).asUInt)
    result(15 downto  8) := sBoxMem(word( 7 downto  0).asUInt)
    result( 7 downto  0) := sBoxMem(word(31 downto 24).asUInt)

    return result
  }

  def hFunc(word: Bits): Bits = {
    val result = Bits(32 bits)

    result( 7 downto  0) := sBoxMem(word( 7 downto  0).asUInt)
    result(15 downto  8) := sBoxMem(word(15 downto  8).asUInt)
    result(23 downto 16) := sBoxMem(word(23 downto 16).asUInt)
    result(31 downto 24) := sBoxMem(word(31 downto 24).asUInt)

    return result
  }
}


/**
  * Key Schedule for a key of 128-bit
  */
class KeyScheduleCore128_Std() extends KeyScheduleCore_Std(128 bits){

  io.key_i        := stateKey.reverse.asBits()

  /** Init command  */
  val initKey = new Area{
    when(io.cmd.valid && io.cmd.mode === KeyScheduleCmdMode.INIT && !cmdready && !autoUpdate ){

      // initialize the statekey
      for(i <- 0 until stateKey.length)  stateKey(i) := keyWord(i)

      when(io.cmd.round === 0xB){ // init cmd with round == 0xB => decrypt mode
        autoUpdate := True
        cntRound   := 1
      }otherwise {               // encrypt mode
        cmdready   := True
        cntRound   := 1
      }
    }
  }

  /** Compute the next state of the key */
  val newKey = new Area{

    stateKey_tmp(0) := stateKey(0)     ^ gFunc(rconMem(cntRound), stateKey(3))
    stateKey_tmp(1) := stateKey_tmp(0) ^ stateKey(1)
    stateKey_tmp(2) := stateKey_tmp(1) ^ stateKey(2)
    stateKey_tmp(3) := stateKey_tmp(2) ^ stateKey(3)
  }


  /** Update Cmd + autoUpdate */
  val updateKey = new Area{

    // Update cmd
    when((io.cmd.valid && io.cmd.mode === KeyScheduleCmdMode.NEXT && !cmdready) && !autoUpdate && !cmdready){

      when(cntRound === io.cmd.round){ //  encrypt mode => update the next key
        cmdready   := True
        autoUpdate := False

        stateKey := stateKey_tmp
        cntRound := cntRound + 1

      }otherwise{  // decrypt mode => initialize the stateKey and set autoUpdate

        when(io.cmd.round === 1){
          cmdready   := True
        }otherwise{
          autoUpdate := True
        }

        cntRound := 1
        for(i <- 0 until stateKey.length) stateKey(i) := keyWord(i)

      }
    }

    // update automatically the key until cntRound == io.cmd.round
    when(autoUpdate){
      stateKey := stateKey_tmp
      cntRound := cntRound + 1

      when(cntRound === io.cmd.round-1){
        cmdready   := True
        autoUpdate := False
      }
    }
  }
}



/**
  * Key Schedule for a key of 192-bit
  */
class KeyScheduleCore192_Std() extends KeyScheduleCore_Std(192 bits){

  /*
  switch(cntDesign){
    is(0){
      /* State 1 */
      stateKey_tmp(0) := stateKey(0) ^ gFunc(rconMem(io.round), stateKey(5))
      stateKey_tmp(1) := stateKey(1) ^ stateKey_tmp(0)
      stateKey_tmp(2) := stateKey(2) ^ stateKey_tmp(1)
      stateKey_tmp(3) := stateKey(3) ^ stateKey_tmp(2)

      stateKey(0) := stateKey_tmp(0)
      stateKey(1) := stateKey_tmp(1)
      stateKey(2) := stateKey_tmp(2)
      stateKey(3) := stateKey_tmp(3)
    }
    is(1){

      /* State 2 */
      stateKey_tmp(4) := stateKey(3) ^ stateKey(4)
      stateKey_tmp(5) := stateKey(5) ^ stateKey_tmp(4)
      stateKey_tmp(0) := stateKey(0) ^ gFunc(rconMem(io.round), keyState_tmp(5))
      stateKey_tmp(1) := stateKey(1) ^ stateKey_tmp(0)

      stateKey(4) := stateKey_tmp(4)
      stateKey(5) := stateKey_tmp(5)
      stateKey(0) := stateKey_tmp(0)
      stateKey(1) := stateKey_tmp(1)
    }
    is(2){
      /* State 3 */
      stateKey_tmp(2) := stateKey(2) ^ stateKey(1)
      stateKey_tmp(3) := stateKey(3) ^ stateKey_tmp(2)
      stateKey_tmp(4) := stateKey(4) ^ stateKey_tmp(3)
      stateKey_tmp(5) := stateKey(5) ^ stateKey_tmp(4)

      stateKey(2) := stateKey_tmp(2)
      stateKey(3) := stateKey_tmp(3)
      stateKey(4) := stateKey_tmp(4)
      stateKey(5) := stateKey_tmp(5)
    }

  }

  */
}


/**
  * Key Schedule for a key of 256-bit
  */
class KeyScheduleCore256_Std() extends KeyScheduleCore_Std(256 bits){

  val cntStage = Reg(UInt(4 bits))

  io.key_i := cntRound(0).mux(
    False -> stateKey.reverse.asBits()(127 downto 0),
    True  -> stateKey.reverse.asBits()(255 downto 128)
  )


  /** Init command  */
  val initKey = new Area{
    when(io.cmd.valid && io.cmd.mode === KeyScheduleCmdMode.INIT && !cmdready && !autoUpdate){

      // initialize the statekey
      for(i <- 0 until stateKey.length)  stateKey(i) := keyWord(i)

      when(io.cmd.round === 0xF){ // init cmd with round == 0xB => decrypt mode
        autoUpdate := True
        cntRound   := 1
      }otherwise {               // encrypt mode
        cmdready   := True
        cntRound   := 1
      }

      cntStage := 1
    }
  }

  /** Compute the next state of the key */
  val newKey = new Area{

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


  /** Update Cmd + autoUpdate */
  val updateKey = new Area{

    // Update cmd
    when((io.cmd.valid && io.cmd.mode === KeyScheduleCmdMode.NEXT && !cmdready) && !autoUpdate && !cmdready){

      when(cntRound === io.cmd.round){ //  encrypt mode => update the next key
        cmdready   := True
        autoUpdate := False

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
          cntStage := cntStage + 1
        }

        cntRound := cntRound + 1

      }otherwise{  // decrypt mode => initialize the stateKey and set autoUpdate

        when(io.cmd.round === 1){
          cmdready   := True
        }otherwise{
          autoUpdate := True
        }

        cntRound := 1
        cntStage :=  1
        for(i <- 0 until stateKey.length) stateKey(i) := keyWord(i)

      }
    }

    // update automatically the key until cntRound == io.cmd.round
    when(autoUpdate){

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
        cntStage := cntStage + 1
      }

      cntRound := cntRound + 1

      when(cntRound === io.cmd.round-1){
        cmdready   := True
        autoUpdate := False
      }
    }
  }
}