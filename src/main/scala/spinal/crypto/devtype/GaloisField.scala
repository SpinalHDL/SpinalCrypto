package spinal.lib.experimental.devTypes

import spinal.core._


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
    (data |<< 1) ^ DBits(polynomial, data.msb)
  }


  /**
    * Multiplication between two Galois filed number
    */
  def multiplication(operand1: DBits, operand2: DBits, poly: String): DBits = {

    val polynomial = Polynomial.str2List(poly)

    assert(polynomial.length == operand1.getWidth, "Polynomial must be of the same order than operands")
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

    println(result.simplify.lispyTree)

    result
  }
}

/**
  * Galois field base class
  * @param value
  * @param poly
  * @param field
  */
abstract class GaloisField(val value: Bits, val poly: String, val field: Int) extends Bundle {

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


case class GF4(v: Bits) extends GaloisField(v, "x^4+x+1", 4){

  override type T = GF4

  def newGF(v: Bits): GF4 = new GF4(v)
}

case class GF8(v: Bits) extends GaloisField(v, "x^8+x^4+x^3+x+1", 8){

  override type T = GF8

  def newGF(v: Bits): GF8 = new GF8(v)
}


object PlayWithGaloisField{

  class TopLevel extends Component{

    val io = new Bundle{
      // GF4 * GF4
      val i1 = in Bits(4 bits)
      val i2 = in Bits(4 bits)
      val o1 = out Bits(4 bits)

      // GF4 * cst
      val o2 = out Bits(4 bits)

      // GF8 * cst
      val i3 = in Bits(8 bits)
      val o3 = out Bits(8 bits)
    }

    val multi = GF4(io.i1) * GF4(io.i2)
    io.o1 := multi.toBits

    val multiCst = GF4(io.i1) * 0x02
    io.o2 := multiCst.toBits

    val multiCst_8 = GF8(io.i3) * 0x0B
    io.o3 := multiCst_8.toBits()

  }


  def main(args: Array[String]): Unit = {
    SpinalVhdl(new TopLevel)
  }
}