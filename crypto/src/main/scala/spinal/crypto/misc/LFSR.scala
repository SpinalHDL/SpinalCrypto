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
package spinal.crypto.misc

import spinal.core._
import spinal.crypto._
import spinal.crypto.PolynomialGF2

import scala.collection.mutable.ListBuffer


/******************************************************************************
  * Linear feedback shift register (LFSR)
  *   There are 2 types of LFSR : Fibonacci and Galois
  *
  * The initial value of the LFSR is called SEED.
  *   !! XOR mode   => seed = all'0 LFSR is stuck
  *   !! XNOR mode  => seed = all'1 LFSR is stuck
  *
  * Polynomial transformation to taps :
  *   x^32 + x^30 + x^11 + x^5 + 1 => Taps(32,30,11,5)
  *
  * Paper     : www.researchgate.net/publication/236109080_FPGA_Implementation_of_8_16_and_32_Bit_LFSR_with_Maximum_Length_Feedback_Polynomial_using_VHDL
  * TestBench : http://www.fpga4fun.com/Counters3.html
  */
object LFSR{

  sealed trait LFSR_MODE
  object XOR  extends LFSR_MODE
  object XNOR extends LFSR_MODE


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
    *         a0     a1    a2     a3     a4     a5     a6     a7
    *        ____   ____   ____   ____   ____   ____   ____   ____
    *   /-->|_f1_|-|_f2_|-|_f3_|-|_f4_|-|_f5_|-|_f6_|-|_f7_|-|_f8_|-
    *   |                              |      |      |             |
    *   \<----------------------------XOR<---XOR<---XOR------------/
    *
    *   e.g : val a = Reg(Bits(8 bits)) init(1)
    *         a := LFSR.Fibonacci(a, p"x^8 + x^6 + x^5 + x^4 + 1")
    *         a := LFSR.Fibonacci(a, Seq(8,6,5,4))
    */
  object Fibonacci {


    /**
      * Create the LFSR with a feedback polynomial
      *
      * @param that       : Input signal
      * @param polynomial : Feedback polynomial or characteristic polynomial for building the LFSR
      */
    def apply(that: Bits, polynomial: PolynomialGF2): Bits = LFSR.Fibonacci(that, polynomial, LFSR.XOR, false)


    /**
      * Create the LFSR with a feedback polynomial
      *
      * @param that          : Input signal
      * @param polynomial    : Feedback polynomial or characteristic polynomial for building the LFSR
      * @param mode          : XOR or XNOR
      * @param extendsPeriod : false => 2^n - 1, true = 2^n
      */
    def apply(that: Bits, polynomial: PolynomialGF2, mode: LFSR_MODE, extendsPeriod: Boolean): Bits = {

      assert(polynomial.coefficient.min == 0 && polynomial.coefficient.length > 1 , s"This is not a valid polynomial for the LFSR $polynomial")
      assert(that.getWidth == polynomial.order,  "Polynomial order must have the same length than the data input")

      LFSR.Fibonacci(that, polynomial.coefficient.filter(_ != 0), mode, extendsPeriod)
    }


    /**
      * Create the LFSR with a sequence of taps
      *
      * @param that   : Input signal
      * @param taps   : Taps for building the LFSR
      */
    def apply(that: Bits, taps: Seq[Int]): Bits = LFSR.Fibonacci(that, taps, LFSR.XOR, false)


    /**
      * Create the LFSR with a sequence of taps
      *
      * @param that          : Input signal
      * @param taps          : Taps for building the LFSR
      * @param mode          : XOR or XNOR
      * @param extendsPeriod : false => 2^n - 1, true => 2^n
      */
    def apply(that: Bits, taps: Seq[Int], mode: LFSR_MODE, extendsPeriod: Boolean): Bits = {

      assert(taps.min != 0, s"This tap ${taps.min} is not valid")
      assert(taps.max == that.getWidth, s"This tap ${taps.max} is too small or too big compare to data input")

      val ret      = cloneOf(that)
      val feedback = taps.map(i => that(i - 1)).reduce(_ ^ _)

      if(extendsPeriod){
        val isEqual = isEqualToX(that, mode)
        ret := (that)(that.high - 1 downto 0) ## operator(feedback ^ isEqual, mode)

      }else{
        ret := (that)(that.high - 1 downto 0) ## operator(feedback, mode)
      }

      ret
    }
  }

  /** Select between XOR and XNOR */
  private def operator(that: Bool, mode: LFSR_MODE): Bool = mode match {
    case LFSR.XNOR => !that
    case LFSR.XOR  => that
  }

  /** Extends period of the LFSR */
  private def isEqualToX(that: Bits, mode: LFSR_MODE): Bool = mode match {
    case LFSR.XNOR => that(that.high - 1 downto 0).asBools.reduce(_ && _) /// === all 1's
    case LFSR.XOR  => !that(that.high - 1 downto 0).asBools.reduce(_ || _) /// === all 0's
  }


  /****************************************************************************
    * LFSR Galois - one-to-many - internal xor gates
    *
    *         a0     a1     a2     a3          a4          a5          a6     a7
    *        ____   ____   ____   ____        ____        ____        ____   ____
    *    /->|_f1_|-|_f2_|-|_f3_|-|_f4_|-XOR->|_f5_|-XOR->|_f6_|-XOR->|_f7_|-|_f8_|-
    *    |_______________________________|___________|___________|_________________|
    *
    *   e.g : val a  = Reg(Bits(8 bits)) init(1)
    *         a := LFSR.Galois(a, p"x^8 + x^6 + x^5 + x^4 + 1")
    *         a := LFSR.Galois(a, Seq(8,6,5,4))
    */
  object Galois {

    /**
      * Create the LFSR with a feedback polynomial
      *
      * @param that       : Input signal
      * @param polynomial : Feedback polynomial or characteristic polynomial for building the LFSR
      */
    def apply(that: Bits, polynomial: PolynomialGF2): Bits = LFSR.Galois(that, polynomial, LFSR.XOR, false)

    /**
      * Create the LFSR with a feedback polynomial
      *
      * @param that          : Input signal
      * @param polynomial    : Feedback polynomial or characteristic polynomial for building the LFSR
      * @param mode          : XOR or XNOR
      * @param extendsPeriod : false => 2^n - 1, true = 2^n
      */
    def apply(that: Bits, polynomial: PolynomialGF2, mode: LFSR_MODE, extendsPeriod: Boolean): Bits = {

      assert(that.getWidth == polynomial.order,  "Polynomial order must have the same length than the data in")
      assert(polynomial.coefficient.min == 0 && polynomial.coefficient.length > 1 , s"This is not a valid polynomial for the LFSR $polynomial")

      LFSR.Galois(that, polynomial.coefficient.filter(_ != 0), mode, extendsPeriod)
    }

    /**
      * Create the LFSR with a sequence of taps
      *
      * @param that   : Input signal
      * @param taps   : Taps for building the LFSR
      */
    def apply(that: Bits, taps: Seq[Int]): Bits = LFSR.Galois(that, taps, LFSR.XOR, false)

    /**
      * Create the LFSR with a sequence of taps
      *
      * @param that          : Input signal
      * @param taps          : Taps for building the LFSR
      * @param mode          : XOR or XNOR
      * @param extendsPeriod : false => 2^n - 1, true = 2^n
      */
    def apply(that: Bits, taps: Seq[Int], mode: LFSR_MODE, extendsPeriod: Boolean): Bits = {

      assert(taps.min != 0, s"This tap ${taps.min} is not valid")
      assert(taps.max == that.getWidth, s"This tap ${taps.max} is too small or too big compare to data input")

      val ret = cloneOf(that)

      val isEqual  = isEqualToX(that, mode)
      val feedback = if(extendsPeriod) that.msb ^ isEqual else that.msb

      def recurLFSR(index: Int): List[Bool] = index match {
        case a if a == 0               => feedback :: recurLFSR(a + 1)
        case a if a == that.getWidth   => Nil
        case a if taps.contains(a)     => operator(that(a - 1) ^ feedback, mode) :: recurLFSR(a + 1)
        case _                         => that(index - 1) :: recurLFSR(index + 1)
      }

      ret := Cat(recurLFSR(0))

      ret
    }
  }
}
