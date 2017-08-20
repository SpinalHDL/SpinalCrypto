package spinal.crypto.symmetric.aes

import spinal.core._
import spinal.lib._


// Key scheduling pattern http://www.samiam.org/key-schedule.html
/**
  *
  * @param storeAllSubKey : used to store all the key during the decryption in order to speed up to processing time
  */
case class KeyScheduleGeneric_Std(val storeAllSubKey: Boolean = false)

case class KeyScheduleRsp_Std() extends Bundle{
  val key_i = Bits(AESCoreSpec.blockWidth)
}

case class KeyScheduleInit_Std(keyWidth: BitCount) extends Bundle{
  val key = Bits(keyWidth)
}

case class KeyScheduleIO_Std(keyWidth: BitCount) extends Bundle{

  val init     = slave(Stream(KeyScheduleInit_Std(keyWidth)))

  val update   = slave(Stream(NoData))
  val round    = in UInt(6 bits)

  val rsp      = out(Flow(KeyScheduleRsp_Std()))
}


// Maybe an option to store the key computed....
class KeyScheduleCore192_Std() extends Component{

  val io = KeyScheduleIO_Std(129 bits)


}


class KeyScheduleCore256_Std() extends Component{}

class KeyScheduleCore128_Std(g: KeyScheduleGeneric_Std = KeyScheduleGeneric_Std()) extends Component{

  val io = KeyScheduleIO_Std(128 bits)

  val cntRound = Reg(UInt(log2Up(10) bits))

  // TODO maybe used the SBox of the core ....
  val sBoxMem = Mem(Bits(8 bits), AESCoreSpec.sBox.map(B(_, 8 bits)))
  val rconMem = Mem(Bits(8 bits), AESCoreSpec.rcon.map(B(_, 8 bits)))

  /* Create a memory to store all keys */
  var keyMem : Mem[Bits] = null
  if(g.storeAllSubKey){
    keyMem = Mem(Bits(128 bits), 10)
  }


  val stateKey     = Reg(Vec(Bits(32 bits), 4))
  val stateKey_tmp = Vec(Bits(32 bits), 4)
  val rspValid     = RegInit(False) setWhen(io.update.valid) clearWhen(!io.update.valid)
  val autoUpdate   = RegInit(False)


  io.update.ready := False
  io.init.ready   := False
  io.rsp.valid    := rspValid
  io.rsp.key_i    := stateKey(0) ## stateKey(1) ## stateKey(2) ## stateKey(3)//Cat(stateKey)//stateKey.asBits // wx(3) ## wx(2) ## wx(1) ## wx(0)


  val keyWord = io.init.key.subdivideIn(32 bits).reverse

  /* Initialize the key state */
  when(io.init.valid){
    for(i <- 0 until stateKey.length){
      stateKey(i) := keyWord(i)
    }
    io.init.ready := True
    cntRound      := 1
  }

  /* Compute the next state of the key */
  stateKey_tmp(0) := stateKey(0)     ^ gFunc(rconMem(io.round), stateKey(3))
  stateKey_tmp(1) := stateKey_tmp(0) ^ stateKey(1)
  stateKey_tmp(2) := stateKey_tmp(1) ^ stateKey(2)
  stateKey_tmp(3) := stateKey_tmp(2) ^ stateKey(3)

  /* Update the current key */
  when(io.update.valid || autoUpdate){
    stateKey := stateKey_tmp
    cntRound := cntRound + 1

    when(cntRound === io.round){
      io.update.ready := True
      autoUpdate := False
    }.elsewhen (!autoUpdate){
      autoUpdate := True
      cntRound   := 1
      for(i <- 0 until stateKey.length){
        stateKey(i) := keyWord(i)
      }
    }
  }

  def gFunc(rc: Bits, word: Bits): Bits = {
    val result = Bits(32 bits)

    result(31 downto 24) := sBoxMem(word(23 downto 16).asUInt) ^ rc
    result(23 downto 16) := sBoxMem(word(15 downto  8).asUInt)
    result(15 downto  8) := sBoxMem(word( 7 downto  0).asUInt)
    result( 7 downto  0) := sBoxMem(word(31 downto 24).asUInt)

    return result
  }
}