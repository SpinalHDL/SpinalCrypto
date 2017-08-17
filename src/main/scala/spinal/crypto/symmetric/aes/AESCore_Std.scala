package spinal.crypto.symmetric.aes

import spinal.core.{Mem, _}
import spinal.crypto.symmetric.{SymmetricCryptoBlockGeneric, SymmetricCryptoBlockIO}
import spinal.lib._
import spinal.lib.fsm.{EntryPoint, State, StateMachine}


/**
  *
  *
  */
class AESCore_Std(keyWidth: BitCount) extends Component{

  val gIO  = SymmetricCryptoBlockGeneric(keyWidth    = keyWidth,
                                        blockWidth  = AESCoreSpec.blockWidth,
                                        useEncDec   = true)

  val io = slave(new SymmetricCryptoBlockIO(gIO))


  val sBoxMem = Mem(Bits(8 bits), AESCoreSpec.sBox.map(B(_, 8 bits)))
  val state   = Reg(Vec(Bits(8 bits), 16))

  val cntRound = Counter(14) // Reg(UInt(4 bits))


  val keyMananger = new KeyManagerCore_Std(keyWidth)
  keyMananger.io.init   := False
  keyMananger.io.update := False
  keyMananger.io.round  := cntRound.resized
  keyMananger.io.key    := io.cmd.key

  io.cmd.ready := False
  io.rsp.valid := False
  io.rsp.block := state.asBits


  val blockByte = io.cmd.block.subdivideIn(8 bits)
  val keyByte   = keyMananger.io.rsp.key_i.subdivideIn(8 bits)


  val sm = new StateMachine{

    val startRound = False

    val sIdle: State = new State with EntryPoint{
      whenIsActive{
        when(io.cmd.valid){
          cntRound.clear()
          keyMananger.io.init := True
          goto(sXOR)
        }
      }
    }
    val sXOR: State = new State{
      whenIsActive{
        when(keyMananger.io.rsp.valid){
          for(i <- 0 until 16){
            state(i) := blockByte(i) ^ keyByte(i)
          }
          goto(sRound)
        }
      }
    }
    val sRound: State = new State{
      whenIsActive{
        startRound := True
      }
    }
    val sFinalRound: State = new State{
      whenIsActive{

      }
    }
  }


  val byteSubstitution = new Area {

    val cntByte = Counter(16)
    val done    = Reg(Bool) init(False) setWhen(cntByte.willOverflowIfInc)

    when(io.cmd.valid && !cntByte.willOverflowIfInc && !done && sm.startRound) {
      cntByte.increment()
      state(cntByte) := sBoxMem(blockByte(cntByte).asUInt)
    }.elsewhen(done){
      // Do nothing
    }.otherwise{
      cntByte.clear()
      done := False
    }

  }

  val shiftRow = new Area{

    val done = False

    when(byteSubstitution.done && io.cmd.valid){
      state(0)  := state(0)
      state(1)  := state(1)
      state(2)  := state(2)
      state(3)  := state(3)
      state(4)  := state(5)
      state(5)  := state(6)
      state(6)  := state(7)
      state(7)  := state(4)
      state(8)  := state(10)
      state(9)  := state(11)
      state(10) := state(8)
      state(11) := state(9)
      state(12) := state(15)
      state(13) := state(12)
      state(14) := state(13)
      state(15) := state(14)
      done := True
    }
  }

  val mixColumn = new Area{

  }

  val keyAddition = new Area{

  }

}









// Key scheduling pattern http://www.samiam.org/key-schedule.html

case class KeyManagerRsp_Std() extends Bundle{
  val key_i = Bits(AESCoreSpec.blockWidth)
}

class KeyManagerCore_Std(keyWidth: BitCount) extends Component{

  //assert(List(128, 192, 256).contains(keyWidth.value), s"AES doesn't support the following key size ${keyWidth.value}")
  assert(List(128).contains(keyWidth.value), s"AES doesn't support the following key size ${keyWidth.value}")

  val sBoxMem = Mem(Bits(8 bits), AESCoreSpec.sBox.map(B(_, 8 bits)))
  val rconMem = Mem(Bits(8 bits), AESCoreSpec.rcon.map(B(_, 8 bits)))


  val io = new Bundle{

    val init     = in Bool
    val update   = in Bool
    val round    = in UInt(6 bits)

    val key      = in Bits(keyWidth)

    val rsp      = out(Flow(KeyManagerRsp_Std()))
  }

  // Store the current key
  val wx = Reg(Vec(Bits(32 bits), 4))


  io.rsp.valid := False
  io.rsp.key_i :=  wx.asBits // wx(3) ## wx(2) ## wx(1) ## wx(0)


  val keyWord = io.key.subdivideIn(32 bits)

  // Compute the new key value
  val w0 = wx(0) ^ gFunc(rconMem(io.round), wx(3).asUInt)
  val w1 = w0 ^ wx(1)
  val w2 = w1 ^ wx(2)
  val w3 = w2 ^ wx(3)

  when(io.init){
    for(i <- 0 until 4){
      wx(i) := keyWord(i)
    }
  }

  when(io.update){
    wx(0) := w0
    wx(1) := w1
    wx(2) := w2
    wx(3) := w3
    io.rsp.valid := True
  }


  def gFunc(rc: Bits, word: UInt): Bits = {
    val result = Bits(32 bits)

    result( 7 downto  0) := sBoxMem(word(15 downto  8)) ^ rc
    result(15 downto  8) := sBoxMem(word(23 downto 16))
    result(23 downto 16) := sBoxMem(word(31 downto 24))
    result(31 downto 24) := sBoxMem(word( 7 downto  0))

    return result
  }
/*
  def hFunc(word: Bits): Bits ={
    val result = cloneOf(word)
    for((r,w) <- result.subdivideIn(32 bits).zip(word.subdivideIn(32 bits))) r := sBoxMem(w)
    result
  }
*/
}


object PlayWithKeyManagerCore_std{
  def main(args: Array[String]): Unit = {
    SpinalVhdl(new KeyManagerCore_Std(128 bits)).printPruned().printUnused()
  }
}



object PlayWithKAESCore_std{
  def main(args: Array[String]): Unit = {
    SpinalVhdl(new AESCore_Std(128 bits)).printPruned().printUnused()
  }
}



