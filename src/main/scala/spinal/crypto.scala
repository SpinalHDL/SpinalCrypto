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
package spinal

import scala.collection.mutable.ListBuffer
import spinal.lib.tools._
import spinal.core._


package object crypto{

//  import languageFeature.implicitConversions
//  implicit lazy val implicitConversions = scala.language.implicitConversions


  /**
    * Used to create polynomial as follow p"x^2 + x + 1"
    */
  implicit class LiteralBuilder(private val sc: StringContext) {
    def p(args: Any*): PolynomialGF2 = str2PolynomialGF2(getString(args))

    private def getString(args: Any*): String = {
      val pi = sc.parts.iterator
      val ai = args.iterator
      val bldr = new StringBuilder(pi.next().toString)

      while (ai.hasNext) {
        if (ai.hasNext && !ai.next.isInstanceOf[List[_]]) bldr append ai.next
        if (pi.hasNext && !pi.next.isInstanceOf[List[_]]) bldr append pi.next
      }

      bldr.result.replace("_", "")
    }
  }


  /**
    * Convert a string into a polynomial
    */
  private[crypto] def str2PolynomialGF2(polyStr: String): PolynomialGF2 = {

    assert(polyStr.length > 0, "Empty  polynomial")

    /**
      * Polynomial str into list of coefficient
      */
    def polynomialStrDecoder(p: String): List[Int] = {

      // Get all coefficient
      var duplicate0 = 0
      val pp = """x\^([0-9]+)""".r
      def getCoef(str: List[String]) : List[Int] = str match{
        case "x" :: tail       => 1 :: getCoef(tail)
        case "1" :: tail       => duplicate0 += 1 ; 0 :: getCoef(tail)
        case "0" :: tail       => duplicate0 += 1 ; getCoef(tail)
        case pp(value) :: tail => value.toInt :: getCoef(tail)
        case Nil               => Nil
        case _                 => throw new Exception(s"The polynomial $p is not valid. ")
      }

      val coefficientList = getCoef(p.split('+').toList)

      // Check if there some duplicate coefficient
      val duplicateCoef = coefficientList.diff(coefficientList.distinct)
      assert(duplicateCoef.length == 0 && duplicate0 <= 1, s"Polynomial $p has duplicate coefficient ${duplicateCoef.mkString(",")}")


      return coefficientList
    }


    /**
      * Polynomial bin/hex into list of coefficient
      */
    def polynomialNumberDecoder(radix: Int, p: String): List[Int] = {

      assert(List(2,16).contains(radix), "The following radix for polynomial is forbidden")

      // remove all _
      var strPoly = p.replace("_", "").toLowerCase

      // convert hexadecimal str into binary string
      var bitCount = -1
      if(radix == 16){
        val split = strPoly.split(''')
        bitCount  = split(0).toInt
        strPoly   = split(1).substring(1)
        strPoly   = BigIntToListBoolean(BigInt(strPoly, 16), bitCount bits).map(b => if(b) "1" else "0").reverse.mkString("")
      }else{
        strPoly = strPoly.substring(1)
      }

      // Convert the binary string into list of coefficient
      val listBuffer = new ListBuffer[Int]()
      for((b,i) <- strPoly.reverse.zipWithIndex){
        if(b == '1') listBuffer.append(i)
      }

      // append for hexadecimal polynomial the higher coefficient
      if(bitCount != -1){
        listBuffer.append(bitCount)
      }

      return listBuffer.toList
    }

    // remove all spaces
    val poly = polyStr.replace(" ", "")

    // detect the format of the string
    val rhex = """[0-9]+\'x[0-9a-fA-F_]+""".r
    val rbin = """b[0-1_]+""".r
    val rstr = """[0-9x\^\+]+""".r

    val polynomial = poly match{
      case rhex() => polynomialNumberDecoder(16, poly)
      case rbin() => polynomialNumberDecoder(2, poly)
      case rstr() => polynomialStrDecoder(poly)
      case _      => throw new Exception("Polynomial format issue")
    }

    return new PolynomialGF2(polynomial.sortWith(_ > _))
  }


}
