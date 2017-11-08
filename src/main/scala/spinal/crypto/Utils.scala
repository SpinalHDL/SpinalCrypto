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
package spinal.crypto

import scala.collection.mutable.ListBuffer


/**
  * Polynomial in Galois Field 2
  */
class PolynomialGF2(val coefficient: List[Int]) {

  def ==(that: PolynomialGF2): Boolean = this.coefficient.sorted == that.coefficient.sorted
  def !=(that: PolynomialGF2): Boolean = !(this == that)

  override def toString: String = {
    (for(coef <- coefficient) yield coef match{
      case 0 => "1"
      case 1 => "x"
      case _ => s"x^$coef"
    }).mkString(" + ")
  }

  /**
    * Return a list of boolean representing the polynomial
    * p"x^4+x+1" => List(true, true, false, false)
    */
  def toBooleanList(): List[Boolean] = {

    val listBuffer = ListBuffer[Boolean]()

    for(i <- 0 until coefficient.max){
      listBuffer.append(coefficient.contains(i))
    }

    return listBuffer.toList
  }
}