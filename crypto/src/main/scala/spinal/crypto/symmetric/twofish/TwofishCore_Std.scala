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
  */
class SBox(keySize: Int) extends Component{


  def nbrSx(keySize: Int) = keySize match{
    case 128 => 3
    case 192 => 4
    case 256 => 5
  }

  def qIndex(keySize: Int) = keySize match{
    case 128 => List(List(0,1,0,1), List(0,0,1,1), List(1,0,1,0))
    case 192 => List(List(1,1,0,0), List(0,1,0,1), List(0,0,1,1), List(1,0,1,0))
    case 256 => List(List(1,0,0,1), List(1,1,0,0), List(0,1,0,1), List(0,0,1,1), List(1,0,1,0))
  }

  val io = new Bundle{
    val in0                    = in Bits(8 bits)
    val out0, out1, out2, out3 = out Bits(8 bits)

    val sX = Vec(Bits(32 bits), nbrSx(keySize))
  }
}

/**
  * S-BOX (128)
  *                 S1                   S0
  *                  |                    |
  *   --- q0 ---     |    --- q0 ---      |     --- q1 ---
  *             |    |    |          |    |    |
  *   --- q1 ---x    |    x--- q0 ---x    |    x--- q0 ---
  *             x-- XOR --x          x-- XOR --x
  *   --- q0 ---x         x--- q1 ---x         x--- q1 ---
  *             |         |          |         |
  *   --- q1 ---           --- q1 ---           --- q0 ---
  */
class S_Box() extends Component{

  val io = new Bundle {
    val s0, s1 = in Bits(32 bits)


    val b1,b2,b3,b4 = in Bits(8 bits)
    val c1,c2,c3,c4 = out Bits(8 bits)

  }

  val q0 = for(_ <- 0 until 6) yield new Qoperation(0)
  val q1 = for(_ <- 0 until 6) yield new Qoperation(1)

  q0(0).io.input := io.b1
  q1(0).io.input := io.b2
  q0(1).io.input := io.b3
  q1(1).io.input := io.b4

  val xor1 = io.s1 ^ (q0(0).io.output ## q1(0).io.output ## q0(1).io.output ## q1(1).io.output)

  q0(2).io.input := xor1(31 downto 24)
  q0(3).io.input := xor1(23 downto 16)
  q1(2).io.input := xor1(15 downto  8)
  q1(3).io.input := xor1( 7 downto  0)

  val xor2 = io.s0 ^ (q0(2).io.output ## q0(3).io.output ## q1(2).io.output ## q1(3).io.output)

  q1(4).io.input := xor2(31 downto 24)
  q0(4).io.input := xor2(23 downto 16)
  q1(5).io.input := xor2(15 downto  8)
  q0(5).io.input := xor2( 7 downto  0)

  io.c1 := q1(4).io.output
  io.c2 := q0(4).io.output
  io.c3 := q1(5).io.output
  io.c4 := q0(5).io.output
}

/*
class MDS() extends Component{

  implicit val polyGF8 = p"x^8+x^6+x^5+x^3+1"

  val io = new Bundle {
    val y0, y1, y2, y3 = in  Bits(8 bits)
    val z0, z1, z2, z3 = out Bits(8 bits)
  }

  val y3_5b = GF8(io.y3) * 0x5B
  val y0_ef = GF8(io.y0) * 0xEF
  val y1_ef = GF8(io.y1) * 0xEF
  val y2_ef = GF8(io.y2) * 0xEF

  io.z0 := (GF8(io.y0) * 0x01 + y1_ef             + GF8(io.y2) * 0x5B + y3_5b).toBits()
  io.z1 := (GF8(io.y0) * 0x5B + y1_ef             + y2_ef             + GF8(io.y3)).toBits()
  io.z2 := (y0_ef             + GF8(io.y1) * 0x5B + GF8(io.y2)        + GF8(io.y3) * 0xEF).toBits()
  io.z3 := (y0_ef             + GF8(io.y1) * 0x5B + y2_ef             + GF8(io.y3) * 0x5B).toBits()

}
*/


class HOperation extends Component {

  val io = new Bundle {
    val input  = in Bits(32 bits)
    val output = out Bits(32 bits)
    val s0, s1 = in Bits(32 bits)
  }

  val sBox = new S_Box()


  sBox.io.b1 := io.input( 7 downto  0)
  sBox.io.b2 := io.input(15 downto  8)
  sBox.io.b3 := io.input(23 downto 16)
  sBox.io.b4 := io.input(31 downto 24)
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

    val y0 = sBox.io.c1
    val y1 = sBox.io.c2
    val y2 = sBox.io.c3
    val y3 = sBox.io.c4

    val y3_5b = GF8(y3) * 0x5B
    val y0_ef = GF8(y0) * 0xEF
    val y1_ef = GF8(y1) * 0xEF
    val y2_ef = GF8(y2) * 0xEF

    val z0 = (GF8(y0)        + y1_ef          + GF8(y2) * 0x5B + y3_5b).toBits()
    val z1 = (GF8(y0) * 0x5B + y1_ef          + y2_ef          + GF8(y3)).toBits()
    val z2 = (y0_ef          + GF8(y1) * 0x5B + GF8(y2)        + GF8(y3) * 0xEF).toBits()
    val z3 = (y0_ef          + GF8(y1)        + y2_ef          + GF8(y3) * 0x5B).toBits()
  }


  io.output := mds.z0 ## mds.z1 ## mds.z2 ## mds.z3

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
    val in_up    = in Bits(32 bits)
    val in_down  = in Bits(32 bits)
    val out_up   = out Bits(32 bits)
    val out_down = out Bits(32 bits)
  }

  val adders = for(i <- 0 until 2) yield new CarryAdder(32)

  adders(0).io.a := io.in_up
  adders(0).io.b := io.in_down

  adders(1).io.a := io.in_down
  adders(1).io.b := adders(0).io.result

  io.out_up   := adders(0).io.result
  io.out_down := adders(1).io.result


}


class TwoFishKeySchedule_128() extends Component {

  val io = new Bundle {
    val odd_in_tk128, even_in_tk128          = in Bits(8 bits)
    val in_key_tk128                         = in Bits(128 bits)
    val out_key_up_tk128, out_key_down_tk128 = out Bits(32 bits)
  }


  // replace by subdividIn 32 bits
  val bytes = io.in_key_tk128.subdivideIn(8 bits)

  val m0 = Cat(List( 0, 1, 2, 3).map(bytes(_)))
  val m1 = Cat(List( 4, 5, 6, 7).map(bytes(_)))
  val m2 = Cat(List( 8, 9,10,11).map(bytes(_)))
  val m3 = Cat(List(12,13,14,15).map(bytes(_)))

  val upper_h = new HOperation()
  upper_h.io.s0    := m2
  upper_h.io.s1    := m0
  upper_h.io.input := io.even_in_tk128.resized

  val lower_h = new HOperation()
  lower_h.io.s0    := m3
  lower_h.io.s1    := m1
  lower_h.io.input := io.odd_in_tk128.resized


  val pht = new PHT()

  pht.io.in_up   := upper_h.io.output
  pht.io.in_down := lower_h.io.output.rotateLeft(8)

  io.out_key_up_tk128   := pht.io.out_up
  io.out_key_down_tk128 := pht.io.out_down.rotateLeft(9)

}


class F_128 extends Component {

  val io = new Bundle{
    val up_in_f128, low_in_f128, s0_in_f128, s1_in_f128, up_key_f128, low_key_f128 = in Bits(32 bits)
    val up_out_f128, low_out_f128 = out Bits(128 bits)
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
  pht.io.out_up := h_lower_128.io.output


  val adder0 = new CarryAdder(32)
  adder0.io.a := pht.io.out_up
  adder0.io.b := io.up_key_f128
  io.up_out_f128 := adder0.io.result

  val adder1 = new CarryAdder(32)
  adder1.io.a := pht.io.out_down
  adder1.io.b := io.low_key_f128
  io.low_out_f128 := adder1.io.result

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

  io.out1 := (funcF.io.up_out_f128 ^ io.in3).rotateLeft(1)

  io.out2 := io.in4.rotateLeft(1) ^ funcF.io.low_out_f128
  io.out3 := io.in1
  io.out4 := io.in2
}



class TwofishCore_Std() extends Component {

  val gIO  = SymmetricCryptoBlockConfig(
    keyWidth    = 128 bits,
    blockWidth  = 64 bits,
    useEncDec   = true
  )

  val io = slave(SymmetricCryptoBlockIO(gIO))

  io.cmd.ready := True
  io.rsp.valid := True
  //io.rsp.block := 0

  val counter = Reg(UInt(8 bits)) init(0)
  counter := (counter + 1) |<< 2

  val keySchedule = new TwoFishKeySchedule_128()
  keySchedule.io.odd_in_tk128  := counter.asBits
  keySchedule.io.even_in_tk128 := (counter + 1).asBits
  keySchedule.io.in_key_tk128  := 0

  io.rsp.block := keySchedule.io.out_key_up_tk128 ## keySchedule.io.out_key_down_tk128


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
