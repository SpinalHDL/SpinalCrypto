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
    val out_key_up, out_key_down = out Bits(32 bits)
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

  io.out_key_up   := pht.io.out_up
  io.out_key_down := pht.io.out_down.rotateLeft(9)

}


class F_128 extends Component {

  val io = new Bundle{
    val up_in_f128, low_in_f128, s0_in_f128, s1_in_f128, up_key_f128, low_key_f128 = in Bits(32 bits)
    val up_out_f128, low_out_f128 = out Bits(32 bits)
  }

  val h_upper_128 = new HOperation()
  h_upper_128.io.input := io.up_in_f128
  h_upper_128.io.s0 := io.s0_in_f128
  h_upper_128.io.s1 := io.s1_in_f128


  val h_lower_128 = new HOperation()
  h_lower_128.io.input := io.low_in_f128.rotateLeft(8)
  h_lower_128.io.s0 := io.s0_in_f128
  h_lower_128.io.s1 := io.s1_in_f128

  val pht = new PHT()
  pht.io.in_up := h_upper_128.io.output
  pht.io.in_down := h_lower_128.io.output

  io.up_out_f128  := CarryAdder(32)(pht.io.out_up,   io.up_key_f128)
  io.low_out_f128 := CarryAdder(32)(pht.io.out_down, io.low_key_f128)

}


class TwoFish_round extends Component{

  val io = new Bundle{
    val in1, in2, in3, in4     = in Bits(32 bits)
    val sFirst, sSecond        = in Bits(32 bits)
    val in_key_up, in_key_down = in Bits(32 bits)
    val out1, out2, out3, out4 = out Bits(32 bits)
  }

  val funcF = new F_128()
  funcF.io.up_in_f128   := io.in1
  funcF.io.low_in_f128  := io.in2
  funcF.io.s0_in_f128   := io.sFirst
  funcF.io.s1_in_f128   := io.sSecond
  funcF.io.up_key_f128  := io.in_key_up
  funcF.io.low_key_f128 := io.in_key_down

  io.out1 := (funcF.io.up_out_f128 ^ io.in3).rotateRight(1)

  io.out2 := io.in4.rotateLeft(1) ^ funcF.io.low_out_f128
  io.out3 := io.in1
  io.out4 := io.in2
}



class TwofishCore_Std() extends Component {

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth    = 128 bits,
    blockWidth  = 128 bits,
    useEncDec   = true
  )

  val io = slave(SymmetricCryptoBlockIO(gIO))

  io.cmd.ready := True
  io.rsp.valid := True
  io.rsp.block := 0

  val counter = Reg(UInt(8 bits)) init(0)

  val keySchedule = new TwoFishKeySchedule_128()



  val sm = new StateMachine{
    val sIdle: State = new State with EntryPoint{
      whenIsActive{

      }
    }
    val sInWhitening: State = new State{
      whenIsActive{

      }
    }
    val sRound: State = new State{
      whenIsActive{

      }
    }
    val sOutWhitening: State = new State{
      whenIsActive{

      }
    }
  }


  val inputWhitening = new Area {

  }

  val round = new Area{

  }

  val outputWhitening = new Area {

  }

}


object PlayWithTwoFish extends App{
  SpinalConfig(
    mode = VHDL
  ).generate(new TwofishCore_Std())
}
