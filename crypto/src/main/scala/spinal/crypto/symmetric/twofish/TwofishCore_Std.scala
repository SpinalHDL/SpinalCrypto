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
package spinal.crypto.symmetric.twofish

import spinal.core._
import spinal.crypto.devtype.GF8
import spinal.lib._
import spinal.crypto.symmetric.{SymmetricCryptoBlockConfig, SymmetricCryptoBlockIO}
import spinal.crypto._
import spinal.lib.fsm._

import scala.collection.mutable.ListBuffer



/**
  * doc          = https://pdfs.semanticscholar.org/cf73/81ecd26b57687837ae679b4108f8cc33b200.pdf
  *                https://www.schneier.com/academic/paperfiles/paper-twofish-paper.pdf
  * pattern      = https://www.schneier.com/code/ecb_ival.txt
  * online tools = http://twofish.online-domain-tools.com/
  */


/**
  *  Q operation
  *
  *        Most                        Lest
  *      Significant                Significant
  *       4 bits                     4 bits
  *        (a)                        (b)
  *         |                          |
  *         x-------------------x------|----------------
  *         |                   |      |                |
  *        XOR <-----------------------x                |
  *         |                   |      |                |
  *         |                   |     >>> 1        a(0),0,0,0
  *         |                   |      |                |
  *         |                   ----> XOR <-------------
  *         |                          |
  *         |                          |
  *        t0                         t1
  *         | (a')                     | (b')
  *         x--------------x-----------|------------------
  *         |              |           |                 |
  *        XOR <---------- | ----------x                 |
  *         |              |           |                 |
  *         |              |         >>> 1          a'(0),0,0,0
  *         |              |           |                 |
  *         |              |--------> XOR <---------------
  *         |                          |
  *        t2                         t3
  *         |                          |
  *       Least                       Most
  *     Significant                Significant
  *      4 bits                      4 bits
  */
object Q0{
  def apply(input: Bits): Bits = {
    val op = new QOperation_Std(0)
    op.io.input := input
    op.io.output
  }
}

object Q1{
  def apply(input: Bits): Bits = {
    val op = new QOperation_Std(1)
    op.io.input := input
    op.io.output
  }
}

class QOperation_Std(i: Int) extends Component {

  assert(i == 0 || i == 1, "")

  val io = new Bundle{
    val input  = in  Bits(8 bits)
    val output = out Bits(8 bits)
  }

  def a: Bits  = io.input(7 downto 4)
  def b: Bits  = io.input(3 downto 0)

  val memT0 = Mem(Bits(4 bits), Twofish.qxT0(i).map(B(_, 4 bits)))
  val memT1 = Mem(Bits(4 bits), Twofish.qxT1(i).map(B(_, 4 bits)))
  val memT2 = Mem(Bits(4 bits), Twofish.qxT2(i).map(B(_, 4 bits)))
  val memT3 = Mem(Bits(4 bits), Twofish.qxT3(i).map(B(_, 4 bits)))

  val a_prime = memT0((a ^ b).asUInt)

  val b1       = a ^ b.rotateRight(1) ^ B(4 bits, 3 -> a(0), default -> False)
  val b1_prime = memT1(b1.asUInt)

  val b1tmp  = a_prime ^ b1_prime.rotateRight(1) ^ B(4 bits, 3 -> a_prime(0), default -> False)

  val a2 = a_prime ^ b1_prime
  io.output(3 downto 0) := memT2(a2.asUInt)
  io.output(7 downto 4) := memT3(b1tmp.asUInt)
}


/**
  * HOperation
  *
  *                  s
  *                  |
  *              ____|____    ______
  *         /-->|_SBox 0_|---|      |
  *         |    ________    |      |
  *         |-->|_SBox 1_|---|      |
  * input --|    ________    | MDS  |---> out
  *         |-->|_SBox 2_|---|      |
  *         |    ________    |      |
  *         \-->|_SBox 3_|---|______|
  *
  */
class HOperation_Std(keyWidth: Int) extends Component {

  val io = new Bundle {
    val s      = in  Vec(Bits(32 bits), Twofish.getWidthOfS(keyWidth))
    val input  = in  Bits(32 bits)
    val output = out Bits(32 bits)
  }


  /**
    * S-BOX (128)
    *                                   S1                    S0
    *                                    |                    |
    *                     --- q0 ---     |     --- q0 ---     |     --- q1 ---
    *                    |          |    |    |          |    |    |          |
    *                    x--- q1 ---x    |    x--- q0 ---x    |    x--- q0 ---x
    *  input(32 bits) ---x          x-- XOR --x          x-- XOR --x          x--- output(32 bits)
    *                    x--- q0 ---x         x--- q1 ---x         x--- q1 ---x
    *                    |          |         |          |         |          |
    *                     --- q1 ---           --- q1 ---           --- q0 ---
    *
    * 128 =>                                        q0q1q0q1 -> XOR -> q0q0q1q1 -> XOR -> q1q0q1q0
    * 192 =>                     q1q1q0q0 -> XOR -> q0q1q0q1 -> XOR -> q0q0q1q1 -> XOR -> q1q0q1q0
    * 256 =>  q1q0q0q1 -> XOR -> q1q1q0q0 -> XOR -> q0q1q0q1 -> XOR -> q0q0q1q1 -> XOR -> q1q0q1q0
    */
  val sBox = new Area {

    /* 256 */
    val xor3 = ifGen(keyWidth > 192){
      io.s(3) ^ (Q1(io.input(31 downto 24)) ## Q0(io.input(23 downto 16)) ## Q0(io.input(15 downto  8)) ## Q1(io.input( 7 downto  0)))
    }

    /* 192 */
    val xor2 = ifGen(keyWidth > 128) {
      val input2 = if (keyWidth != 192) xor3 else io.input

      io.s(2) ^ (Q0(input2(31 downto 24)) ## Q0(input2(23 downto 16)) ## Q1(input2(15 downto  8)) ## Q1(input2( 7 downto  0)))
    }

    /* 128 */
    val input_1 = if (keyWidth > 128) xor2 else io.input

    val xor1   = io.s(1) ^ (Q1(input_1(31 downto 24)) ## Q0(input_1(23 downto 16)) ## Q1(input_1(15 downto  8)) ## Q0(input_1( 7 downto  0)))
    val xor0   = io.s(0) ^ (Q1(xor1(31 downto 24)) ## Q1(xor1(23 downto 16)) ## Q0(xor1(15 downto  8)) ## Q0(xor1( 7 downto  0)))
    val output = Q0(xor0(31 downto 24)) ## Q1(xor0(23 downto 16)) ## Q0(xor0(15 downto  8)) ## Q1(xor0( 7 downto  0))
  }


  /**
    * Maximum Distance Separable matrices (MDS)
    *
    *   /   \   /             \    /  \
    *  | z0 |   | 01 EF 5B 5B |   | y0 |
    *  | z1 |   | 5B EF EF 01 | * | y1 |
    *  | z2 | = | EF 5B 01 EF |   | y2 |
    *  | z3 |   | EF 01 EF 5B |   | y3 |
    *  \   /    \            /    \   /
    *
    */
  val mds = new Area{

    implicit val polyGF8 = p"x^8+x^6+x^5+x^3+1"

    def y0: Bits = sBox.output( 7 downto  0)
    def y1: Bits = sBox.output(15 downto  8)
    def y2: Bits = sBox.output(23 downto 16)
    def y3: Bits = sBox.output(31 downto 24)

    val y3_5b = GF8(y3) * 0x5B
    val y0_ef = GF8(y0) * 0xEF
    val y1_ef = GF8(y1) * 0xEF
    val y2_ef = GF8(y2) * 0xEF

    val z0 = (GF8(y0)        + y1_ef          + GF8(y2) * 0x5B + y3_5b).toBits()
    val z1 = (GF8(y0) * 0x5B + y1_ef          + y2_ef          + GF8(y3)).toBits()
    val z2 = (y0_ef          + GF8(y1) * 0x5B + GF8(y2)        + GF8(y3) * 0xEF).toBits()
    val z3 = (y0_ef          + GF8(y1)        + y2_ef          + GF8(y3) * 0x5B).toBits()
  }

  io.output := mds.z3 ## mds.z2 ## mds.z1 ## mds.z0
}


/**
  * Pseudo-Hadamard Transform (PHT)
  */
class PHT extends Component {

  val io = new Bundle {
    val din   = in  Vec(Bits(32 bits), 2)
    val dout  = out Vec(Bits(32 bits), 2)
  }

  io.dout(0) := (io.din(0).asUInt + io.din(1).asUInt).asBits
  io.dout(1) := (io.din(1).asUInt + io.dout(0).asUInt).asBits
}


/**
  * Key scheduler
  *
  *           m(2,0)
  *           __|_               _____
  *          |    |             |     |
  * 2i ----> | H0 |------------>|     |------------> Subkey 2i
  *          |____|             |     |
  *                             | PHT |
  *           ____              |     |
  *          |    |             |     |
  * 2i+1 --> | H1 |--> <<< 8 -->|     |--> <<< 9 --> Subkey 2i+1
  *          |____|             |_____|
  *             |
  *           m(1,3)
  *
  */
class TwofishKeySchedule_Std(keyWidth: Int) extends Component {

  val io = new Bundle {
    val round   = in  UInt(8 bits)
    val inKey   = in  Bits(keyWidth bits)
    val outKey  = out Vec(Bits(32 bits), 2)
  }

  // round * 2
  val round = io.round |<< 1

  // m
  val m = io.inKey.subdivideIn(32 bits).reverse.map(EndiannessSwap(_))

  /** H Operation */
  val h = List.fill(2)(new HOperation_Std(keyWidth))

  keyWidth match {
    case 128 =>  h(0).io.s  := Vec(m(0), m(2))
    case 192 =>  h(0).io.s  := Vec(m(0), m(2), m(4))
    case 256 =>  h(0).io.s  := Vec(m(0), m(2), m(4), m(6))
  }

  h(0).io.input := (round ## round ## round ## round).asBits.resized

  keyWidth match {
    case 128 =>  h(1).io.s  := Vec(m(1), m(3))
    case 192 =>  h(1).io.s  := Vec(m(1), m(3), m(5))
    case 256 =>  h(1).io.s  := Vec(m(1), m(3), m(5), m(7))
  }

  val round_nxt    = round + 1
  h(1).io.input := (round_nxt ## round_nxt ## round_nxt ## round_nxt).asBits.resized


  /** PHT */
  val pht = new PHT()
  pht.io.din(0) := h(0).io.output
  pht.io.din(1) := h(1).io.output.rotateLeft(8)

  io.outKey(0) := pht.io.dout(0)
  io.outKey(1) := pht.io.dout(1).rotateLeft(9)
}


/**
  * F operation
  *                            ____     ____________   Key 2r+8
  *                           |    |   |    PHT    |     |
  *     din ----------------> | H0 |-->|--> + -----|---> + ------> dout
  *                           |____|   |   |   |   |
  *                            ____    |   |   |   |    Key 2r+9
  *             ________      |    |   |   |   |   |     |
  *     din  --|_<<< 1__|---> | H1 |-->|-----> + --|---> + ------> dout
  *                           |____|   |___________|
  */
class FOperation_Std(keyWidth: Int) extends Component {

  val io = new Bundle{
    val din  = in  Vec(Bits(32 bits), 2)
    val s    = in  Vec(Bits(32 bits), Twofish.getWidthOfS(keyWidth))
    val key  = in  Vec(Bits(32 bits), 2)
    val dout = out Vec(Bits(32 bits), 2)
  }

  /** H */
  val h = List.fill(2)(new HOperation_Std(keyWidth))

  h(0).io.input := io.din(0)
  h(0).io.s     := io.s

  h(1).io.input := io.din(1).rotateLeft(8)
  h(1).io.s     := io.s


  /** PHT */
  val pht = new PHT()
  pht.io.din(0) := h(0).io.output
  pht.io.din(1) := h(1).io.output

  io.dout(0) := (pht.io.dout(0).asUInt + io.key(0).asUInt).asBits
  io.dout(1) := (pht.io.dout(1).asUInt + io.key(1).asUInt).asBits
}


/**
  * TwoFish_round
  *
  *     _________________________________________________________
  *    |                                                         |
  *    |                   Data(128 bits)                        |
  *    |_________________________________________________________|
  *           |     |                               |     |
  *   K0 --> XOR   XOR <-- K1               K2 --> XOR   XOR <-- K3
  *           |     |     ____________________      |     |
  *           |     x--->|                    |--> XOR   >>>1
  *           |     |    |         F          |     |     |
  *           x-----|--->|____________________|-----|--> XOR
  *           |     |                              >>>1   |
  *           \     \                               /    /
  *                           15 rounds
  *
  *           |     |                               |     |
  *   K4 --> XOR   XOR <-- K5               K6 --> XOR   XOR <-- K7
  *     ______|_____|_______________________________|_____|______
  *    |                                                         |
  *    |                   output(128 bits)                      |
  *    |_________________________________________________________|
  *
  * @param keyWidth
  */
class TwofishRound_Std(keyWidth: Int) extends Component{

  val io = new Bundle{
    val din               = in  Vec(Bits(32 bits), 4)
    val s                 = in  Vec(Bits(32 bits), Twofish.getWidthOfS(keyWidth))
    val key               = in  Vec(Bits(32 bits), 2)
    val dout              = out Vec(Bits(32 bits), 4)
    val encryption        = in  Bool()
  }

  /** F operation */
  val fOp = new FOperation_Std(keyWidth)
  fOp.io.din := Vec(io.din(0), io.din(1))
  fOp.io.s   := io.s
  fOp.io.key := io.key


  /** output */
  when(io.encryption) {
    io.dout(0) := (fOp.io.dout(0) ^ io.din(2)).rotateRight(1)
    io.dout(1) := io.din(3).rotateLeft(1) ^ fOp.io.dout(1)
  }otherwise{
    io.dout(0) := io.din(2).rotateLeft(1) ^ fOp.io.dout(0)
    io.dout(1) := (fOp.io.dout(1) ^ io.din(3)).rotateRight(1)
  }

  io.dout(2) := io.din(0)
  io.dout(3) := io.din(1)
}


/**
  * TwoFishCore_Std
  *
  * @param keyWidth
  */
class TwofishCore_Std(keyWidth: BitCount) extends Component {

  // check the size of the input key width
  assert(keyWidth.value == 128 || keyWidth.value == 192 || keyWidth.value == 256)

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth    = keyWidth,
    blockWidth  = Twofish.blockWidth,
    useEncDec   = true
  )

  /** IO */
  val io = slave(SymmetricCryptoBlockIO(gIO))

  /* Global variable */
  val round  = Reg(UInt(8 bits))
  val data   = Vec(Reg(Bits(32 bits)), 4)

  /** Key scheduler */
  val keySchedule = new TwofishKeySchedule_Std(keyWidth.value)
  keySchedule.io.inKey := io.cmd.key
  keySchedule.io.round := round


  /**
    * Reed-Solomon Matrix
    */
  val rs = new Area {

    def matrixRSMultiplication(m0: Bits, m1: Bits, m2: Bits, m3: Bits, m4: Bits, m5: Bits, m6: Bits, m7: Bits): Bits = {

      implicit val polyGF8 = p"x^8+x^6+x^3+x^2+1"

      val s0 = (GF8(m0)        + GF8(m1) * 0xA4 + GF8(m2) * 0x55 + GF8(m3) * 0x87 + GF8(m4) * 0x5A + GF8(m5) * 0x58 + GF8(m6) * 0xDB + GF8(m7) * 0x9E).toBits()
      val s1 = (GF8(m0) * 0xA4 + GF8(m1) * 0x56 + GF8(m2) * 0x82 + GF8(m3) * 0xF3 + GF8(m4) * 0x1E + GF8(m5) * 0xC6 + GF8(m6) * 0x68 + GF8(m7) * 0xE5).toBits()
      val s2 = (GF8(m0) * 0x02 + GF8(m1) * 0xA1 + GF8(m2) * 0xFC + GF8(m3) * 0xC1 + GF8(m4) * 0x47 + GF8(m5) * 0xAE + GF8(m6) * 0x3D + GF8(m7) * 0x19).toBits()
      val s3 = (GF8(m0) * 0xA4 + GF8(m1) * 0x55 + GF8(m2) * 0x87 + GF8(m3) * 0x5A + GF8(m4) * 0x58 + GF8(m5) * 0xDB + GF8(m6) * 0x9E + GF8(m7) * 0x03).toBits()
      s3 ## s2 ## s1 ## s0
    }

    val m  = io.cmd.key.subdivideIn(8 bits).reverse

    val s0 = matrixRSMultiplication(m(0), m(1), m(2),  m(3),  m(4),  m(5),  m(6),  m(7))
    val s1 = matrixRSMultiplication(m(8), m(9), m(10), m(11), m(12), m(13), m(14), m(15))

    val s2 = ifGen(keyWidth.value > 128){
      matrixRSMultiplication(m(16), m(17), m(18), m(19), m(20), m(21), m(22), m(23))
    }

    val s3 = ifGen(keyWidth.value > 192){
      matrixRSMultiplication(m(24), m(25), m(26), m(27), m(28), m(29), m(30), m(31))
    }

    val sList = ListBuffer(s0, s1)
    if(keyWidth.value > 128) sList += s2
    if(keyWidth.value > 192) sList += s3

    val s = Vec(sList.reverse)
  }


  /**
    * Whitening input
    */
  val inputWhitening = new Area {
    val enable    = False
    val firstPass = False

    when(enable && firstPass){
      data(0) := EndiannessSwap(io.cmd.block(127 downto 96)) ^ keySchedule.io.outKey(0)
      data(1) := EndiannessSwap(io.cmd.block( 95 downto 64)) ^ keySchedule.io.outKey(1)
    }
    when(enable && !firstPass){
      data(2) := EndiannessSwap(io.cmd.block( 63 downto 32)) ^ keySchedule.io.outKey(0)
      data(3) := EndiannessSwap(io.cmd.block( 31 downto  0)) ^ keySchedule.io.outKey(1)
    }
  }

  /**
    * Round Operation
    */
  val roundArea = new Area{

    val enable = False

    val opRound = new TwofishRound_Std(keyWidth.value)

    opRound.io.din        := data
    opRound.io.s          := rs.s
    opRound.io.key        := keySchedule.io.outKey
    opRound.io.encryption := io.cmd.enc

    when(enable){
      data := opRound.io.dout
    }
  }

  /**
    * Output whitening
    */
  val outputWhitening = new Area {
    val enable    = False
    val firstPass = False

    when(enable && firstPass){
      data(2) := data(2) ^ keySchedule.io.outKey(0)
      data(3) := data(3) ^ keySchedule.io.outKey(1)
    }
    when(enable && !firstPass){
      data(0) := data(0) ^ keySchedule.io.outKey(0)
      data(1) := data(1) ^ keySchedule.io.outKey(1)
    }
  }


  /**
    * State machine
    */
  val sm = new StateMachine{

    val rspValid = False

    val sIdle: State = new State with EntryPoint{
      whenIsActive{
        when(io.cmd.valid && !io.cmd.ready){
          round := io.cmd.enc ? U(0, round.getBitsWidth bits) | U(2, round.getBitsWidth bits)
          goto(sInWhitening_1)
        }
      }
    }

    val sInWhitening_1: State = new State{
      whenIsActive{
        round := round + 1
        inputWhitening.enable    := True
        inputWhitening.firstPass := True
        goto(sInWhitening_2)
      }
    }

    val sInWhitening_2: State = new State{
      whenIsActive{
        round := io.cmd.enc ? U(4, round.getWidth bits) | U(19, round.getWidth bits)
        inputWhitening.enable := True
        goto(sRound)
      }
    }

    val sRound: State = new State{
      whenIsActive{
        roundArea.enable := True
        round := io.cmd.enc ? (round + 1) | (round - 1)
        when(round === (io.cmd.enc ? U(19) | U(4))){
          round := io.cmd.enc ? U(2, round.getWidth bits) | U(0, round.getWidth bits)
          goto(sOutWhitening_1)
        }
      }
    }

    val sOutWhitening_1: State = new State{
      whenIsActive{
        round := round + 1
        outputWhitening.enable    := True
        outputWhitening.firstPass := True
        goto(sOutWhitening_2)
      }
    }

    val sOutWhitening_2: State = new State{
      whenIsActive{
        outputWhitening.enable := True
        rspValid := True
        goto(sIdle)
      }
    }
  }


  io.cmd.ready := RegNext(sm.rspValid, False)
  io.rsp.valid := io.cmd.ready
  io.rsp.block := (EndiannessSwap(data(2)) ## EndiannessSwap(data(3)) ## EndiannessSwap(data(0)) ## EndiannessSwap(data(1)))

}