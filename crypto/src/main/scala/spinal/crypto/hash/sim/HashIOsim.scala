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
package spinal.crypto.hash.sim


import spinal.core._
import spinal.core.sim._
import spinal.crypto._
import spinal.crypto.hash.{LITTLE_endian, EndiannessMode, HashCoreIO}

import scala.util.Random


object HashIOsim {

  def initializeIO(dut: HashCoreIO): Unit ={
    dut.init      #= false
    dut.cmd.valid #= false
    dut.cmd.msg.randomize()
    dut.cmd.size.randomize()
    dut.cmd.last.randomize()
  }


  def doSim(dut: HashCoreIO, clockDomain: ClockDomain, lengthString: Int, endianess: EndiannessMode, msg: String = null)(refCrypto: (String) => Array[Byte]): Unit = {

    val byteSizeMsg = dut.cmd.msg.getWidth / 8

    // init Hash
    clockDomain.waitActiveEdge()
    dut.init      #= true
    clockDomain.waitActiveEdge()
    dut.init      #= false
    clockDomain.waitActiveEdge()

    // Generate a random message + compute the reference hash
    var msgHex    = if(msg == null) List.fill(lengthString)(Random.nextPrintableChar()).mkString("") else msg
    val refDigest = refCrypto(msgHex)

    // number of iteration
    var index = math.ceil(msgHex.length  / byteSizeMsg.toDouble).toInt

    // Send all block of message
    while(index != 0) {

      val (msg, isLast) = if (msgHex.length > byteSizeMsg) (msgHex.substring(0, byteSizeMsg) -> false) else (msgHex + 0.toChar.toString * (byteSizeMsg - msgHex.length) -> true)

      dut.cmd.valid #= true
      dut.cmd.msg   #= BigInt(0x00.toByte +: (if(endianess == LITTLE_endian) (msg.map(_.toByte).reverse.toArray) else (msg.map(_.toByte).toArray))  )// Add 00 in front in order to get a positif number
      dut.cmd.size  #= BigInt(if (isLast) msgHex.length - 1 else 0)
      dut.cmd.last  #= isLast

      clockDomain.waitActiveEdge()

      // Wait the response
      if (isLast){
        waitUntil(dut.rsp.valid.toBoolean == true)

        val rtlDigest = CastByteArray(dut.rsp.digest.toBigInt.toByteArray, dut.rsp.digest.getWidth)

        if(endianess == LITTLE_endian){
          assert(CastByteArray(refDigest, dut.rsp.digest.getWidth).sameElements(Endianness(rtlDigest)), s"REF != RTL ${BigIntToHexString(BigInt(refDigest))} != ${BigIntToHexString(BigInt(Endianness(rtlDigest)))}")
        }else{
          assert(CastByteArray(refDigest, dut.rsp.digest.getWidth).sameElements(rtlDigest), s"REF != RTL ${BigIntToHexString(BigInt(refDigest))} != ${BigIntToHexString(BigInt(rtlDigest))}")
        }


        clockDomain.waitActiveEdge()
      }else {
        waitUntil(dut.cmd.ready.toBoolean == true)
      }

      initializeIO(dut)

      clockDomain.waitActiveEdge()

      index -= 1
      msgHex = msgHex.drop(byteSizeMsg)
    }
  }
}

