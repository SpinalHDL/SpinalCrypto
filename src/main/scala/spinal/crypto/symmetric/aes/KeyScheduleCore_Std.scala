package spinal.crypto.symmetric.aes

import spinal.core._
import spinal.lib._


// Key scheduling pattern http://www.samiam.org/key-schedule.html
/**
  *
  * @param storeAllSubKey : used to store all the key during the decryption in order to speed up to processing time
  */
case class KeyScheduleGeneric_Std(val keyWidth: BitCount,
                                  val storeAllSubKey: Boolean = false)


case class KeyScheduleInit_Std(keyWidth: BitCount) extends Bundle{
  val key = Bits(keyWidth)
}

object KeyScheduleCmdMode extends SpinalEnum{
  val INIT, NEXT = newElement()
}

case class KeyScheduleCmd(keyWidth: BitCount) extends Bundle{
  val mode  = KeyScheduleCmdMode()
  val round = UInt(6 bits)
  val key   = Bits(keyWidth)
}

case class KeyScheduleIO_Std(keyWidth: BitCount) extends Bundle{

  val cmd    = slave(Stream(KeyScheduleCmd(keyWidth)))

  val key_i  = out Bits(keyWidth)
}


// Maybe an option to store the key computed....

abstract class KeyScheduleCore_Std(g: KeyScheduleGeneric_Std) extends Component{

  val io = KeyScheduleIO_Std(g.keyWidth)

  val cntRound = Reg(UInt(log2Up(AESCoreSpec.nbrRound(g.keyWidth)) + 2 bits))

  val rconMem = Mem(Bits(8 bits), AESCoreSpec.rcon.map(B(_, 8 bits)))
  val sBoxMem = Mem(Bits(8 bits), AESCoreSpec.sBox.map(B(_, 8 bits)))  // TODO maybe used the SBox of the core


  def gFunc(rc: Bits, word: Bits): Bits = {
    val result = Bits(32 bits)

    result(31 downto 24) := sBoxMem(word(23 downto 16).asUInt) ^ rc
    result(23 downto 16) := sBoxMem(word(15 downto  8).asUInt)
    result(15 downto  8) := sBoxMem(word( 7 downto  0).asUInt)
    result( 7 downto  0) := sBoxMem(word(31 downto 24).asUInt)

    return result
  }
}

class KeyScheduleCore256_Std(g: KeyScheduleGeneric_Std = KeyScheduleGeneric_Std(256 bits)) extends KeyScheduleCore_Std(g){}

class KeyScheduleCore192_Std(g: KeyScheduleGeneric_Std = KeyScheduleGeneric_Std(192 bits)) extends KeyScheduleCore_Std(g){}


class KeyScheduleCore128_Std(g: KeyScheduleGeneric_Std = KeyScheduleGeneric_Std(128 bits)) extends KeyScheduleCore_Std(g){

  /* Create a memory to store all keys */
  //var keyMem : Mem[Bits] = null
  //if(g.storeAllSubKey){
  //  keyMem = Mem(Bits(128 bits), 10)
  //}

  val stateKey     = Reg(Vec(Bits(32 bits), 4))
  val stateKey_tmp = Vec(Bits(32 bits), 4)
  val autoUpdate   = RegInit(False)


  val cmdready    = RegInit(False)
  io.cmd.ready    := cmdready
  io.key_i        := stateKey.reverse.asBits()

  when(cmdready) {cmdready := False}

  val keyWord = io.cmd.key.subdivideIn(32 bits).reverse

  /* Initialize the key state */
  when(io.cmd.valid && io.cmd.mode === KeyScheduleCmdMode.INIT && !cmdready){
    for(i <- 0 until stateKey.length){
      stateKey(i) := keyWord(i)
    }
    when(io.cmd.round === 0x0B){
      autoUpdate := True
      cntRound := 1
    }otherwise {
      cmdready   := True
      cntRound   := 1
    }
  }

  /* Compute the next state of the key */
  stateKey_tmp(0) := stateKey(0)     ^ gFunc(rconMem(cntRound), stateKey(3))
  stateKey_tmp(1) := stateKey_tmp(0) ^ stateKey(1)
  stateKey_tmp(2) := stateKey_tmp(1) ^ stateKey(2)
  stateKey_tmp(3) := stateKey_tmp(2) ^ stateKey(3)

  /* Update the current key */
  when((io.cmd.valid && io.cmd.mode === KeyScheduleCmdMode.NEXT && !cmdready) && !autoUpdate && !cmdready){

    when(cntRound === io.cmd.round){
      cmdready   := True
      autoUpdate := False

      stateKey := stateKey_tmp
      cntRound := cntRound + 1

    }.elsewhen (!autoUpdate){
      when(io.cmd.round === 1){
        cmdready := True
      }otherwise{
        autoUpdate := True
      }
      cntRound   := 1
      for(i <- 0 until stateKey.length){
        stateKey(i) := keyWord(i)
      }
    }
  }

  when(autoUpdate){
    stateKey := stateKey_tmp
    cntRound := cntRound + 1

    when(cntRound === io.cmd.round-1){
      cmdready   := True
      autoUpdate := False
    }
  }

}