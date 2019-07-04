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
    val op = new QOperation(0)
    op.io.input := input
    return op.io.output
  }
}
object Q1{
  def apply(input: Bits): Bits = {
    val op = new QOperation(1)
    op.io.input := input
    return op.io.output
  }
}
class QOperation(i: Int) extends Component {

  assert(i == 0 || i == 1, "")

  val io = new Bundle{
    val input  = in  Bits(8 bits)
    val output = out Bits(8 bits)
  }

  val a  = io.input(7 downto 4)
  val b  = io.input(3 downto 0)

  val memT0 = Mem(Bits(4 bits), Twofish.qxT0(i).map(B(_, 4 bits)))
  val memT1 = Mem(Bits(4 bits), Twofish.qxT1(i).map(B(_, 4 bits)))
  val memT2 = Mem(Bits(4 bits), Twofish.qxT2(i).map(B(_, 4 bits)))
  val memT3 = Mem(Bits(4 bits), Twofish.qxT3(i).map(B(_, 4 bits)))

  val a_prime = memT0((a ^ b).asUInt)

  val b1       = a ^ b.rotateRight(1) ^ B(4 bits, 3 -> a(0), default -> False)
  val b1_prime = memT1(b1.asUInt)

  val b1tmp  = a_prime ^ b1_prime.rotateRight(1)  ^ B(4 bits, 3 -> a_prime(0), default -> False)

  val a2 = a_prime ^ b1_prime
  io.output(3 downto 0) := memT2(a2.asUInt)
  io.output(7 downto 4) := memT3(b1tmp.asUInt)
}


/**
  * SBOX rework
  *  128 =>                                        q0q1q0q1 -> XOR -> q0q0q1q1 -> XOR -> q1q0q1q0
  *  192 =>                     q1q1q0q0 -> XOR -> q0q1q0q1 -> XOR -> q0q0q1q1 -> XOR -> q1q0q1q0
  *  256 =>  q1q0q0q1 -> XOR -> q1q1q0q0 -> XOR -> q0q1q0q1 -> XOR -> q0q0q1q1 -> XOR -> q1q0q1q0
  *
  * S-BOX (128)
  *                  S1                   S0
  *                   |                    |
  *    --- q0 ---     |     --- q0 ---     |     --- q1 ---
  *              |    |    |          |    |    |
  *    --- q1 ---x    |    x--- q0 ---x    |    x--- q0 ---
  *              x-- XOR --x          x-- XOR --x
  *    --- q0 ---x         x--- q1 ---x         x--- q1 ---
  *              |         |          |         |
  *    --- q1 ---           --- q1 ---           --- q0 ---
  */
class SBox(keySize: Int) extends Component{


  def nbrSx(keySize: Int) = keySize match{
    case 128 => 2
    case 192 => 3
    case 256 => 4
  }

  val index_128 = List(List(0,1,0,1), List(0,0,1,1), List(1,0,1,0))
  val index_192 = List(List(1,1,0,0)) ++ index_128
  val index_256 = List(List(1,0,0,1)) ++ index_192

  def qIndex(keySize: Int) = keySize match{
    case 128 => index_128
    case 192 => index_192
    case 256 => index_256
  }

  val io = new Bundle{
    val in0, in1, in2, in3     = in  Bits(8 bits)
    val out0, out1, out2, out3 = out Bits(8 bits)

    val sX = Vec(Bits(32 bits), nbrSx(keySize))
  }


  val index = qIndex(keySize)

  val nbrQ0 = index.flatten.count(_ == 0)
  val nbrQ1 = index.flatten.count(_ == 1)

  val q0 = for(_ <- 0 until nbrQ0) new QOperation(0)
  val q1 = for(_ <- 0 until nbrQ1) new QOperation(1)

  // assign index to each
  var iQ0 = 0
  var iQ1 = 0
  val indexQQ = ListBuffer[ListBuffer[(Int, Int)]]()
  for(i <- 0 until index.size){
    val inner = ListBuffer[(Int, Int)]()

  }


  for(i <- 0 until index.size){
    var tmpInput : Bits = 0

    if(i == 0){
      tmpInput = (io.in0 ## io.in1 ## io.in2 ## io.in3)
    }else{

    }
  }
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
class HOperation extends Component {

  val io = new Bundle {
    val s       = in  Vec(Bits(32 bits), 2)
    val input   = in  Bits(32 bits)
    val output  = out Bits(32 bits)
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
    */
  val sBox = new Area {

    val xor1 = io.s(1) ^ (Q1(io.input(31 downto 24)) ## Q0(io.input(23 downto 16)) ## Q1(io.input(15 downto  8)) ## Q0(io.input( 7 downto  0)))

    val xor2 = io.s(0) ^ (Q1(xor1(31 downto 24)) ## Q1(xor1(23 downto 16)) ## Q0(xor1(15 downto  8)) ## Q0(xor1( 7 downto  0)))

    val output = Q0(xor2(31 downto 24)) ## Q1(xor2(23 downto 16)) ## Q0(xor2(15 downto  8)) ## Q1(xor2( 7 downto  0))
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

    val y0 = sBox.output( 7 downto  0)
    val y1 = sBox.output(15 downto  8)
    val y2 = sBox.output(23 downto 16)
    val y3 = sBox.output(31 downto 24)

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



object CarryAdder{

  def apply(size: Int)(a: Bits, b: Bits): Bits = {
    val adder = new CarryAdder(size)
    adder.io.a := a
    adder.io.b := b
    return adder.io.result
  }

}

class CarryAdder(size: Int) extends Component{

  val io = new Bundle{
    val a      = in Bits(size bits)
    val b      = in Bits(size bits)
    val result = out Bits(size bits)
  }

  var c = False
  for (i <- 0 until size) {

    val a = io.a(i)
    val b = io.b(i)

    io.result(i) := a ^ b ^ c
    c \= (a & b) | (c & (a ^ b))
  }
}


/**
  * Pseudo-Hadamard Transform (PHT)
  */
class PHT extends Component {

  val io = new Bundle {
    val din   = in  Vec(Bits(32 bits), 2)
    val dout  = out Vec(Bits(32 bits), 2)
  }

  io.dout(0) := CarryAdder(32)(io.din(0), io.din(1))
  io.dout(1) := CarryAdder(32)(io.din(1), io.dout(0))
}


/**
  * Key scheduler
  */
class TwoFishKeySchedule() extends Component {

  val io = new Bundle {
    val round   = in  UInt(8 bits)
    val inKey   = in  Bits(128 bits)
    val outKey  = out Vec(Bits(32 bits), 2)
  }

  val round = io.round |<< 1

  val m = io.inKey.subdivideIn(32 bits).reverse.map(EndiannessSwap(_))

  /** H Operation */
  val upper_h = new HOperation()
  upper_h.io.s     := Vec(m(0), m(2))
  upper_h.io.input := (round ## round ## round ## round).asBits.resized

  val lower_h = new HOperation()
  lower_h.io.s     := Vec(m(1), m(3))
  val round_nxt    = round + 1
  lower_h.io.input := (round_nxt ## round_nxt ## round_nxt ## round_nxt).asBits.resized


  /** PHT */
  val pht = new PHT()
  pht.io.din(0) := upper_h.io.output
  pht.io.din(1) := lower_h.io.output.rotateLeft(8)

  io.outKey(0) := pht.io.dout(0)
  io.outKey(1) := pht.io.dout(1).rotateLeft(9)

}


/**
  * F operation
  *                            ____     ____________   K2r+8
  *                           |    |   |    PHT    |     |
  *   up_in ----------------> | H  |-->|--> + -----|---> + ------> up_out
  *                           |____|   |   |   |   |
  *                            ____    |   |   |   |    K2r+9
  *             ________      |    |   |   |   |   |     |
  *   low_in --|_<<< 1__|---> | H  |-->|-----> + --|---> + ------> low_out
  *                           |____|   |___________|
  */
class FOperation extends Component {

  val io = new Bundle{
    val din    = in  Vec(Bits(32 bits), 2)
    val s      = in  Vec(Bits(32 bits), 2)
    val key    = in  Vec(Bits(32 bits), 2)
    val dout   = out Vec(Bits(32 bits), 2)
  }

  val h_upper = new HOperation()
  h_upper.io.input := io.din(0)
  h_upper.io.s     := io.s


  val h_lower = new HOperation()
  h_lower.io.input := io.din(1).rotateLeft(8)
  h_lower.io.s     := io.s

  val pht = new PHT()
  pht.io.din(0)   := h_upper.io.output
  pht.io.din(1) := h_lower.io.output

  io.dout(0) := CarryAdder(32)(pht.io.dout(0),   io.key(0))
  io.dout(1) := CarryAdder(32)(pht.io.dout(1), io.key(1))
}


class TwoFish_round extends Component{

  val io = new Bundle{
    val din               = in  Vec(Bits(32 bits), 4)
    val s                 = in  Vec(Bits(32 bits), 2)
    val key               = in  Vec(Bits(32 bits), 2)
    val dout              = out Vec(Bits(32 bits), 4)
    val encryption        = in  Bool
  }

  val fOp = new FOperation()
  fOp.io.din     := Vec(io.din(0), io.din(1))
  fOp.io.s       := io.s
  fOp.io.key     := io.key


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



class TwofishCore_Std(keyWidth: BitCount) extends Component {

  assert(keyWidth.value == 128)

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth    = keyWidth,
    blockWidth  = keyWidth,
    useEncDec   = true
  )

  val io = slave(SymmetricCryptoBlockIO(gIO))

  val round  = Reg(UInt(8 bits))
  val data   = Vec(Reg(Bits(32 bits)), 4)

  /** Key scheduler */
  val keySchedule = new TwoFishKeySchedule()
  keySchedule.io.inKey := io.cmd.key
  keySchedule.io.round := round



  /**
    * Reed-Solomon Matrix
    */
  val rs = new Area {

    implicit val polyGF8 = p"x^8+x^6+x^3+x^2+1"

    val m  = io.cmd.key.subdivideIn(8 bits).reverse

    val s0_0 = (GF8(m(0))        + GF8(m(1)) * 0xA4 + GF8(m(2)) * 0x55 + GF8(m(3)) * 0x87 + GF8(m(4)) * 0x5A + GF8(m(5)) * 0x58 + GF8(m(6)) * 0xDB + GF8(m(7)) * 0x9E).toBits()
    val s0_1 = (GF8(m(0)) * 0xA4 + GF8(m(1)) * 0x56 + GF8(m(2)) * 0x82 + GF8(m(3)) * 0xF3 + GF8(m(4)) * 0x1E + GF8(m(5)) * 0xC6 + GF8(m(6)) * 0x68 + GF8(m(7)) * 0xE5).toBits()
    val s0_2 = (GF8(m(0)) * 0x02 + GF8(m(1)) * 0xA1 + GF8(m(2)) * 0xFC + GF8(m(3)) * 0xC1 + GF8(m(4)) * 0x47 + GF8(m(5)) * 0xAE + GF8(m(6)) * 0x3D + GF8(m(7)) * 0x19).toBits()
    val s0_3 = (GF8(m(0)) * 0xA4 + GF8(m(1)) * 0x55 + GF8(m(2)) * 0x87 + GF8(m(3)) * 0x5A + GF8(m(4)) * 0x58 + GF8(m(5)) * 0xDB + GF8(m(6)) * 0x9E + GF8(m(7)) * 0x03).toBits()

    val s1_0 = (GF8(m(8))        + GF8(m(9)) * 0xA4 + GF8(m(10)) * 0x55 + GF8(m(11)) * 0x87 + GF8(m(12)) * 0x5A + GF8(m(13)) * 0x58 + GF8(m(14)) * 0xDB + GF8(m(15)) * 0x9E).toBits()
    val s1_1 = (GF8(m(8)) * 0xA4 + GF8(m(9)) * 0x56 + GF8(m(10)) * 0x82 + GF8(m(11)) * 0xF3 + GF8(m(12)) * 0x1E + GF8(m(13)) * 0xC6 + GF8(m(14)) * 0x68 + GF8(m(15)) * 0xE5).toBits()
    val s1_2 = (GF8(m(8)) * 0x02 + GF8(m(9)) * 0xA1 + GF8(m(10)) * 0xFC + GF8(m(11)) * 0xC1 + GF8(m(12)) * 0x47 + GF8(m(13)) * 0xAE + GF8(m(14)) * 0x3D + GF8(m(15)) * 0x19).toBits()
    val s1_3 = (GF8(m(8)) * 0xA4 + GF8(m(9)) * 0x55 + GF8(m(10)) * 0x87 + GF8(m(11)) * 0x5A + GF8(m(12)) * 0x58 + GF8(m(13)) * 0xDB + GF8(m(14)) * 0x9E + GF8(m(15)) * 0x03).toBits()

    val s = Vec((s1_3 ## s1_2 ## s1_1 ## s1_0),
                (s0_3 ## s0_2 ## s0_1 ## s0_0))
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
    * Round
    */
  val roundArea = new Area{

    val enable = False

    val f = new TwoFish_round()

    f.io.din        := data
    f.io.s          := rs.s
    f.io.key        := keySchedule.io.outKey
    f.io.encryption := io.cmd.enc

    when(enable){
      data := f.io.dout
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
          round    := io.cmd.enc ? U(0, round.getBitsWidth bits) | U(2, round.getBitsWidth bits)
          goto(sInWhitening_1)
        }
      }
    }

    val sInWhitening_1: State = new State{
      whenIsActive{
        round    := round + 1
        inputWhitening.enable := True
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
        outputWhitening.enable := True
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
  io.rsp.valid := RegNext(sm.rspValid, False)
  io.rsp.block := (EndiannessSwap(data(2)) ## EndiannessSwap(data(3)) ## EndiannessSwap(data(0)) ## EndiannessSwap(data(1)))


}


object PlayWithTwoFish extends App{
  SpinalConfig(
    mode = VHDL
  ).generate(new TwofishCore_Std(128 bits))
}
