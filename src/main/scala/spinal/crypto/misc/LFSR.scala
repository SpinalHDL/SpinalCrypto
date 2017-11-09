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
package spinal.crypto.misc

import spinal.core._
import spinal.crypto._
import spinal.crypto.PolynomialGF2

import scala.collection.mutable.ListBuffer

// Paper : www.researchgate.net/publication/236109080_FPGA_Implementation_of_8_16_and_32_Bit_LFSR_with_Maximum_Length_Feedback_Polynomial_using_VHDL
// TODO : fpga4fun lfsrtestbench
// TODO : mode xor and nxor


/******************************************************************************
  * Linear feedback shift register (LFSR)
  *   There are 2 types of LFSR : Fibonacci and Galois
  *
  * The initial value of the LFSR is called SEED. If the seed is equal to 0,
  * the LFSR is stuck.
  *
  * Polynomial transformation to taps :
  *   x^32 + x^30 + x^11 + x^5 + 1 => Taps(32,30,11,5)
  *
  */
object LFSR{

  /**
    * Polynomial for maximum period LFSR length (max period = 2^n-1, n number of shift register)
    * https://we.archive.org/web/20161007061934/http://courses.cse.tamu.edu/csce680/walker/lfsr_table.pdf
    */
  def polynomial_8bits   = p"x^8 + x^6 + x^5 + x^4 + 1"
  def taps_8bits         = Seq(8, 6, 5, 4)
  def polynomial_16bits  = p"x^16 + x^14 + x^13 + x^11 + 1"
  def taps_16bits        = Seq(16, 14, 13, 11)
  def polynomial_32bits  = p"x^32 + x^30 + x^26 + x^25 + 1"
  def taps_32bits        = Seq(32, 30, 26, 25)
  def polynomial_64bits  = p"x^64 + x^63 + x^61 + x^60 + 1"
  def taps_64bits        = Seq(64, 63, 61, 60)
  def polynomial_128bits = p"x^128 + x^127 + x^126 + x^121 + 1"
  def taps_128bits       = Seq(128, 127, 126, 121)
  def polynomial_256bits = p"x^256 + x^254 + x^251 + x^246 + 1"
  def taps_256bits       = Seq(256, 254, 251, 246)



  /****************************************************************************
    * LFSR Fibonacci - many-to-one - external xor gates
    *
    *         a7     a6     a5     a4     a3     a2     a1     a0
    *        ____   ____   ____   ____   ____   ____   ____   ____
    *   /-->|_f1_|-|_f2_|-|_f3_|-|_f4_|-|_f5_|-|_f6_|-|_f7_|-|_f8_|-
    *   |                              |      |      |             |
    *   \<----------------------------XOR<---XOR<---XOR------------/
    *
    *   e.g : val a = Reg(Bits(8 bits)) init(1)
    *         a := LFSR.Fibonacci(a, p"x^8 + x^6 + x^5 + x^4 + 1")
    *         a := LFSR.Fibonacci(a, Seq(8,6,5,4))
    */
  object Fibonacci{

    /**
      * Create the LFSR with a feedback polynomial
      *
      * @param that       : Input signal
      * @param polynomial : Feedback polynomial or characteristic polynomial for building the LFSR
      */
    def apply(that: Bits, polynomial: PolynomialGF2): Bits = {

      assert(polynomial.coefficient.min == 0 && polynomial.coefficient.length > 1 , s"This is not a valid polynomial for the LFSR $polynomial")
      assert(that.getWidth == polynomial.order,  "Polynomial order must have the same length than the data input")

      LFSR.Fibonacci(that, polynomial.coefficient.filter(_ != 0))
    }

    /**
      * Create the LFSR with a sequence of taps
      *
      * @param that   : Input signal
      * @param taps   : Taps for building the LFSR
      */
    def apply(that: Bits, taps: Seq[Int]): Bits = {

      assert(taps.min != 0, s"This tap ${taps.min} is not valid")
      assert(taps.max == that.getWidth, s"This tap ${taps.max} is too small or too big compare to data input")

      val ret      = cloneOf(that)
      val feedback = (taps.map(i => that(that.getWidth - i)).reduce(_ ^ _)).dontSimplifyIt().setName("feedback")

      ret := feedback ## (that >> 1)

      ret
    }
  }


  /****************************************************************************
    * LFSR Galois - one-to-many - internal xor gates
    *
    *         a7     a6          a5          a4          a3     a2     a1     a0
    *        ____   ____        ____        ____        ____   ____   ____   ____
    *    /->|_f8_|-|_f7_|-XOR->|_f6_|-XOR->|_f5_|-XOR->|_f4_|-|_f3_|-|_f2_|-|_f1_|-
    *    |_________________|___________|___________|_______________________________|
    *
    *   e.g : val a  = Reg(Bits(8 bits)) init(1)
    *         a := LFSR.Galois(a, p"x^8 + x^6 + x^5 + x^4 + 1")
    *         a := LFSR.Galois(a, Seq(8,6,5,4))
    */
  object Galois{

    /**
      * Create the LFSR with a feedback polynomial
      *
      * @param that       : Input signal
      * @param polynomial : Feedback polynomial or characteristic polynomial for building the LFSR
      */
    def apply(that: Bits, polynomial: PolynomialGF2): Bits = {

      assert(that.getWidth == polynomial.order,  "Polynomial order must have the same length than the data in")
      assert(polynomial.coefficient.min == 0 && polynomial.coefficient.length > 1 , s"This is not a valid polynomial for the LFSR $polynomial")

      LFSR.Galois(that, polynomial.coefficient.filter(_ != 0))
    }

    /**
      * Create the LFSR with a sequence of taps
      *
      * @param that   : Input signal
      * @param taps   : Taps for building the LFSR
      */
    def apply(that: Bits, taps: Seq[Int]): Bits = {

      assert(taps.min != 0, s"This tap ${taps.min} is not valid")
      assert(taps.max == that.getWidth, s"This tap ${taps.max} is too small or too big compare to data input")

      val ret = cloneOf(that)

      val bitsList = new ListBuffer[Bool]()

      for (index <- that.high to 0 by -1){
        if (index == that.high) {
          bitsList += that.lsb
        }else if(taps.contains(index + 1)) {
          bitsList += that(index + 1) ^ that.lsb
        }else{
          bitsList += that(index + 1)
        }
      }

      ret := Cat(bitsList.reverse)

      ret
    }
  }
}
