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
package spinal.crypto.primitive.keccak

import scala.collection.mutable

object Keccak {

  /**
    * The rotation offsets r[x,y]
    */
  private var pRawOffset : mutable.LinkedHashMap[(Int, Int), Int] = mutable.LinkedHashMap((0,0) -> 0)


  /**
    * Precompute the map pRawOffset
    *
    *   1. For all z such that 0≤z<w, let A′ [0, 0,z] = A[0, 0,z].
    *   2. Let (x, y) = (1, 0)
    *   3. For t from 0 to 23:
    *     a. for all z such that 0≤z<w, let A′[x, y,z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
    *     b. let (x, y) = (y, (2x+3y) mod 5).
    */
  private def initRawOffset() = {
    var x = 1
    var y = 0

    for(t <- 0 to 23){

      pRawOffset += ((x, y) -> ((t + 1) * (t + 2)) / 2)

      val tmpX = x
      x = y
      y = (2 * tmpX + 3 * y) % 5
    }
  }

  initRawOffset()


  def pOffset(x: Int, y: Int, modulo: Int): Int = {
    return pRawOffset.get((x, y)).get % modulo
  }


  /**
    * The round constants RC[i] are given in the table below for the maximum lane size 64.
    * For smaller sizes, they are simply truncated.
    */
  def RC : List[BigInt] = List(
    BigInt("0000000000000001", 16),	BigInt("0000000000008082", 16),
    BigInt("800000000000808A", 16),	BigInt("8000000080008000", 16),
    BigInt("000000000000808B", 16),	BigInt("0000000080000001", 16),
    BigInt("8000000080008081", 16), BigInt("8000000000008009", 16),
    BigInt("000000000000008A", 16),	BigInt("0000000000000088", 16),
    BigInt("0000000080008009", 16), BigInt("000000008000000A", 16),
    BigInt("000000008000808B", 16), BigInt("800000000000008B", 16),
    BigInt("8000000000008089", 16), BigInt("8000000000008003", 16),
    BigInt("8000000000008002", 16), BigInt("8000000000000080", 16),
    BigInt("000000000000800A", 16), BigInt("800000008000000A", 16),
    BigInt("8000000080008081", 16), BigInt("8000000000008080", 16),
    BigInt("0000000080000001", 16), BigInt("8000000080008008", 16)
  )



}
