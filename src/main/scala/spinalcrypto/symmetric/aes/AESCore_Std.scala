package spinalcrypto.symmetric.aes


import spinal.core.{Mem, _}
import spinal.lib._
import spinalcrypto.symmetric.{SymmetricCryptoCoreGeneric, SymmetricCryptoCoreIO}


/**
  *
  *
  */
class AESCore_Std(keyWidth: BitCount) extends Component{

  assert(List(128, 192, 256).contains(keyWidth.value), s"AES doesn't support the following key size ${keyWidth.value}")

  val gIO  = SymmetricCryptoCoreGeneric(keyWidth    = keyWidth,
                                        blockWidth  = AESCoreSpec.blockWidth,
                                        useEncDec   = true)

  val io = slave(new SymmetricCryptoCoreIO(gIO))


  val sBox   = Mem(Bits(8 bits), AESCoreSpec.sBox.map(B(_, 8 bits)))
  val rndCnt = Reg(UInt(log2Up(AESCoreSpec.nbrRound(keyWidth)) bits))









  // Key scheduling pattern http://www.samiam.org/key-schedule.html
  val keyScheduling = new Area{

    val nbrKeyWord = keyWidth.value / 32

    val key     = Bits(keyWidth)
    val keyWord = key.subdivideIn(32 bits)

    val update  = Bool
    val init    = Bool

    val rcon    = Mem(Bits(8 bits), AESCoreSpec.rcon.map(B(_, 8 bits)))

    val wx = Reg(Vec(Bits(32 bits), 4))

    // Compute the new key value
    val w0 = wx(0) ^ g(rcon(rndCnt + 1), wx(3))
    val w1 = w0 ^ wx(1)
    val w2 = w1 ^ wx(2)
    val w3 = w2 ^ wx(3)

    // key Initialization
    when(init){
      for(i <- 0 until nbrKeyWord){
        wx(i) := keyWord(i)
      }
    }

    // Key update
    when(update){
      wx(0) := w0
      wx(1) := w1
      wx(2) := w2
      wx(3) := w3
    }

    def g(rc: Bits, word: Bits): Bits = {
      val result = cloneOf(word)

      result( 7 downto  0) := sBox(word(15 downto  8)) ^ rc
      result(15 downto  8) := sBox(word(23 downto 16))
      result(23 downto 16) := sBox(word(31 downto 24))
      result(31 downto 24) := sBox(word( 7 downto  0))

      return result
    }
  }

}







