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
package spinal.crypto.devtype

import spinal.core._
import spinal.crypto._


object GaloisField{

  /**
    * XTimes function (used for the multiplication)
    *
    * e.g: GF4 with polynomial x^4 + x + 1
    *                Input
    *  _______________|_________________
    * |_b3_|_b2______________________b0_|
    *  ____/_______/_______/________/___
    * |_b2_|_____________________b0_|_0_|
    *                    |
    *  poly: 00b3b3 --->XOR
    *                    |
    *                 Output
    */
  private def xtimes(data: DBits, polynomial: List[Boolean]): DBits = {
    (data |<< 1) ^ DBits(polynomial.reverse.init, data.msb)
  }


  /**
    * Multiplication between two Galois field number
    */
  def multiplication(operand1: DBits, operand2: DBits, poly: PolynomialGF2): DBits = {

    val polynomial = poly.toBooleanList()

    assert(polynomial.length == operand1.getWidth + 1, "Polynomial must be of the same order than operands")
    assert(operand1.getWidth == operand2.getWidth, "The size of the operands are different")

    var tmp    = operand1
    var result = DBits("Bits", operand1.getWidth bits)

    for(i <- 0 until operand1.getWidth){

      val andOperand = DBits(List.fill(operand1.getWidth)(true), operand2(i))

      if(i==0){
        result = andOperand & tmp
      }else{
        tmp     = xtimes(tmp, polynomial)
        result  = (andOperand & tmp) ^ result
      }
    }

    result
  }
}

/**
  * Galois field base class
  */
abstract class GaloisField(val value: Bits, val poly: PolynomialGF2) extends Bundle {

  val field: Int = poly.coefficient.max

  assert(value.getWidth == field, s"GF$field support only Bits on $field bits ")

  type T <: GaloisField

  def newGF(v: Bits): T

  def *(that: T): T = {
    assert(this.poly == that.poly, "Irreducible polynomial is not the same")
    newGF(GaloisField.multiplication(DBits("a", this.value), DBits("b", that.value), poly).toBits)
  }

  def *(that: BigInt): T = {
    assert(log2Up(that) <= this.field, s"that is bigger than $field bits")
    newGF(GaloisField.multiplication(DBits("a", this.value), DBitsLiteral(that, this.field bits), poly).toBits)
  }


  def +(that: T): T = newGF(this.value ^ that.value)
  def -(that: T): T = this + that

  def ^(that: T): T = this + that


  def toBits(): Bits = this.value
}


case class GF4(v: Bits)(implicit poly: PolynomialGF2) extends GaloisField(v, poly){

  override type T = GF4

  def newGF(v: Bits): GF4 = new GF4(v)
}


case class GF8(v: Bits)(implicit poly: PolynomialGF2) extends GaloisField(v, poly){

  override type T = GF8

  def newGF(v: Bits): GF8 = new GF8(v)
}