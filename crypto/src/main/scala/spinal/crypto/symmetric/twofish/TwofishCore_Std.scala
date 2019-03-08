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
    val op = new Qoperation(0)
    op.io.input := input
    return op.io.output
  }
}
object Q1{
  def apply(input: Bits): Bits = {
    val op = new Qoperation(1)
    op.io.input := input
    return op.io.output
  }
}
class Qoperation(i: Int) extends Component {

  assert(i == 0 || i == 1, "")

  val io = new Bundle{
    val input  = in Bits(8 bits)
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

  val q0 = for(_ <- 0 until nbrQ0) new Qoperation(0)
  val q1 = for(_ <- 0 until nbrQ1) new Qoperation(1)

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
class S_Box() extends Component{

  val io = new Bundle {
    val s0, s1 = in Bits(32 bits)

    val input  = in  Bits(32 bits)
    val output = out Bits(32 bits)
  }


  val xor1 = io.s1 ^ (Q1(io.input(31 downto 24)) ## Q0(io.input(23 downto 16)) ## Q1(io.input(15 downto  8)) ## Q0(io.input( 7 downto  0)))

  val xor2 = io.s0 ^ (Q1(xor1(31 downto 24)) ## Q1(xor1(23 downto 16)) ## Q0(xor1(15 downto  8)) ## Q0(xor1( 7 downto  0)))

  io.output( 7 downto  0) := Q1(xor2( 7 downto  0))
  io.output(15 downto  8) := Q0(xor2(15 downto  8))
  io.output(23 downto 16) := Q1(xor2(23 downto 16))
  io.output(31 downto 24) := Q0(xor2(31 downto 24))
}




class HOperation extends Component {

  val io = new Bundle {
    val input  = in Bits(32 bits)
    val output = out Bits(32 bits)
    val s0, s1 = in Bits(32 bits)
  }

  val sBox = new S_Box()


  sBox.io.input := io.input

  sBox.io.s0 := io.s0
  sBox.io.s1 := io.s1


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

    val y0 = sBox.io.output( 7 downto  0)
    val y1 = sBox.io.output(15 downto  8)
    val y2 = sBox.io.output(23 downto 16)
    val y3 = sBox.io.output(31 downto 24)

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

class CarryAdder(size : Int) extends Component{
  val io = new Bundle{
    val a = in Bits(size bits)
    val b = in Bits(size bits)
    val result = out Bits(size bits)      //result = a + b
  }

  var c = False                   //Carry, like a VHDL variable
  for (i <- 0 until size) {
    //Create some intermediate value in the loop scope.
    val a = io.a(i)
    val b = io.b(i)

    //The carry adder's asynchronous logic
    io.result(i) := a ^ b ^ c
    c \= (a & b) | (c & (a ^ b))    //variable assignment
  }
}


/**
  * Pseudo-Hadamard Transform (PHT)
  */
class PHT extends Component {

  val io = new Bundle {
    val in_up,  in_down   = in Bits(32 bits)
    val out_up, out_down  = out Bits(32 bits)
  }

  io.out_up   := CarryAdder(32)(io.in_up,   io.in_down)
  io.out_down := CarryAdder(32)(io.in_down, io.out_up)
}

/**
  * Key scheduler
  */
class TwoFishKeySchedule_128() extends Component {

  val io = new Bundle {
    val round                    = in  UInt(8 bits)
    val inKey                    = in  Bits(128 bits)
    val outKeyEven, outKeyOdd = out Bits(32 bits)
  }

  val round = io.round |<< 1

  // replace by subdividIn 32 bits
  val bytes = io.inKey.subdivideIn(32 bits).reverse

  val m0 = bytes(0)
  val m1 = bytes(1)
  val m2 = bytes(2)
  val m3 = bytes(3)

  val upper_h = new HOperation()
  upper_h.io.s0    := m0
  upper_h.io.s1    := m2
  upper_h.io.input := (round ## round ## round ## round).asBits.resized

  val lower_h = new HOperation()
  lower_h.io.s0    := m1
  lower_h.io.s1    := m3
  val round_nxt    = round + 1
  lower_h.io.input := (round_nxt ## round_nxt ## round_nxt ## round_nxt).asBits.resized


  val pht = new PHT()

  pht.io.in_up   := upper_h.io.output
  pht.io.in_down := lower_h.io.output.rotateLeft(8)

  io.outKeyEven := pht.io.out_up
  io.outKeyOdd := pht.io.out_down.rotateLeft(9)

}


class F_128 extends Component {

  val io = new Bundle{
    val up_in_f128, low_in_f128   = in Bits(32 bits)
    val s0, s1    = in Bits(32 bits)
    val keyEven, keyOdd = in Bits(32 bits)
    val up_out_f128, low_out_f128 = out Bits(32 bits)
  }

  val h_upper_128 = new HOperation()
  h_upper_128.io.input := io.up_in_f128
  h_upper_128.io.s0 := io.s0
  h_upper_128.io.s1 := io.s1


  val h_lower_128 = new HOperation()
  h_lower_128.io.input := io.low_in_f128.rotateLeft(8)
  h_lower_128.io.s0 := io.s0
  h_lower_128.io.s1 := io.s1

  val pht = new PHT()
  pht.io.in_up := h_upper_128.io.output
  pht.io.in_down := h_lower_128.io.output

  io.up_out_f128  := CarryAdder(32)(pht.io.out_up,   io.keyEven)
  io.low_out_f128 := CarryAdder(32)(pht.io.out_down, io.keyOdd)

}


class TwoFish_round extends Component{

  val io = new Bundle{
    val in1, in2, in3, in4     = in  Bits(32 bits)
    val s0, s1                 = in  Bits(32 bits)
    val keyEven, keyOdd        = in  Bits(32 bits)
    val out1, out2, out3, out4 = out Bits(32 bits)
  }

  val funcF = new F_128()
  funcF.io.up_in_f128   := io.in1
  funcF.io.low_in_f128  := io.in2
  funcF.io.s0       := io.s0
  funcF.io.s1       := io.s1
  funcF.io.keyEven  := io.keyEven
  funcF.io.keyOdd   := io.keyOdd

  io.out1 := (funcF.io.up_out_f128 ^ io.in3).rotateRight(1)

  io.out2 := io.in4.rotateLeft(1) ^ funcF.io.low_out_f128
  io.out3 := io.in1
  io.out4 := io.in2
}



class TwofishCore_Std(keyWidth: BitCount) extends Component {

  assert(keyWidth.value == 128)

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth    = keyWidth,
    blockWidth  = 128 bits,
    useEncDec   = true
  )

  val io = slave(SymmetricCryptoBlockIO(gIO))

  val round = Reg(UInt(8 bits)) init(0)

  val keySchedule = new TwoFishKeySchedule_128()
  keySchedule.io.inKey := io.cmd.key
  keySchedule.io.round := round

  val data_1, data_2, data_3, data_4 = Reg(Bits(32 bits))


  val rs = new Area{
    implicit val polyGF8 = p"x^8+x^6+x^3+x^2+1"

    val m = io.cmd.key.subdivideIn(8 bits)

    val s0_0 = (GF8(m(0))        + GF8(m(1)) * 0xA4 + GF8(m(2)) * 0x55 + GF8(m(3)) * 0x87 + GF8(m(4)) * 0x5A + GF8(m(5)) * 0x58 + GF8(m(6)) * 0xDB + GF8(m(7)) * 0x9E).toBits()
    val s0_1 = (GF8(m(0)) * 0xA4 + GF8(m(1)) * 0x56 + GF8(m(2)) * 0x82 + GF8(m(3)) * 0xF3 + GF8(m(4)) * 0x1E + GF8(m(5)) * 0xC6 + GF8(m(6)) * 0x68 + GF8(m(7)) * 0xE5).toBits()
    val s0_2 = (GF8(m(0)) * 0X02 + GF8(m(1)) * 0xA1 + GF8(m(2)) * 0xFC + GF8(m(3)) * 0xC1 + GF8(m(4)) * 0x47 + GF8(m(5)) * 0xAE + GF8(m(6)) * 0x3D + GF8(m(7)) * 0x19).toBits()
    val s0_3 = (GF8(m(0)) * 0XA4 + GF8(m(1)) * 0x55 + GF8(m(2)) * 0x87 + GF8(m(3)) * 0x5A + GF8(m(4)) * 0x58 + GF8(m(5)) * 0xDB + GF8(m(6)) * 0x9E + GF8(m(7)) * 0x03).toBits()

    val s1_0 = (GF8(m(8))        + GF8(m(9)) * 0xA4 + GF8(m(10)) * 0x55 + GF8(m(11)) * 0x87 + GF8(m(12)) * 0x5A + GF8(m(13)) * 0x58 + GF8(m(14)) * 0xDB + GF8(m(15)) * 0x9E).toBits()
    val s1_1 = (GF8(m(8)) * 0xA4 + GF8(m(9)) * 0x56 + GF8(m(10)) * 0x82 + GF8(m(11)) * 0xF3 + GF8(m(12)) * 0x1E + GF8(m(13)) * 0xC6 + GF8(m(14)) * 0x68 + GF8(m(15)) * 0xE5).toBits()
    val s1_2 = (GF8(m(8)) * 0X02 + GF8(m(9)) * 0xA1 + GF8(m(10)) * 0xFC + GF8(m(11)) * 0xC1 + GF8(m(12)) * 0x47 + GF8(m(13)) * 0xAE + GF8(m(14)) * 0x3D + GF8(m(15)) * 0x19).toBits()
    val s1_3 = (GF8(m(8)) * 0XA4 + GF8(m(9)) * 0x55 + GF8(m(10)) * 0x87 + GF8(m(11)) * 0x5A + GF8(m(12)) * 0x58 + GF8(m(13)) * 0xDB + GF8(m(14)) * 0x9E + GF8(m(15)) * 0x03).toBits()

    val s0 = (s0_3 ## s0_2 ## s0_1 ## s0_0)
    val s1 = (s1_3 ## s1_2 ## s1_1 ## s1_0)
  }


  val inputWhitening = new Area {
    val enable = False
    val firstPass = False

    when(enable && firstPass){
      data_1 := io.cmd.block(127 downto 96) ^ keySchedule.io.outKeyEven
      data_2 := io.cmd.block( 95 downto 64) ^ keySchedule.io.outKeyOdd
    }
    when(enable && !firstPass){
      data_3 := io.cmd.block( 63 downto 32) ^ keySchedule.io.outKeyEven
      data_4 := io.cmd.block( 31 downto  0) ^ keySchedule.io.outKeyOdd
    }
  }

  val roundArea = new Area{

    val enable = False

    val f = new TwoFish_round()

    f.io.in1     := data_1
    f.io.in2     := data_2
    f.io.in3     := data_3
    f.io.in4     := data_4
    f.io.s0      := rs.s0
    f.io.s1      := rs.s1
    f.io.keyEven := keySchedule.io.outKeyEven
    f.io.keyOdd  := keySchedule.io.outKeyOdd

    when(enable){
      data_3 := f.io.out3
      data_4 := f.io.out4
      data_1 := f.io.out1
      data_2 := f.io.out2
    }

  }

  val outputWhitening = new Area {
    val enable    = False
    val firstPass = False

    when(enable && firstPass){
      data_3 := data_3 ^ keySchedule.io.outKeyEven
      data_4 := data_4 ^ keySchedule.io.outKeyOdd
    }
    when(enable && !firstPass){
      data_1 := data_1 ^ keySchedule.io.outKeyEven
      data_2 := data_2 ^ keySchedule.io.outKeyOdd
    }
  }


  val sm = new StateMachine{

    val rspValid = False

    val sIdle: State = new State with EntryPoint{
      whenIsActive{
        when(io.cmd.valid && io.cmd.ready){
          round := 0
          goto(sInWhitening_1)
        }
      }
    }
    val sInWhitening_1: State = new State{
      whenIsActive{
        round := round + 1
        inputWhitening.enable := True
        inputWhitening.firstPass := True
        goto(sInWhitening_2)
      }
    }
    val sInWhitening_2: State = new State{
      whenIsActive{
        round := 4
        inputWhitening.enable := True
        goto(sRound)
      }
    }
    val sRound: State = new State{
      whenIsActive{
        roundArea.enable := True
        round := round + 1
        when(round === 19){
          round := 2
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
  io.rsp.block := (EndiannessSwap(data_3) ## EndiannessSwap(data_4) ## EndiannessSwap(data_1) ## EndiannessSwap(data_2))


}


object PlayWithTwoFish extends App{
  SpinalConfig(
    mode = VHDL
  ).generate(new TwofishCore_Std(128 bits))
}
