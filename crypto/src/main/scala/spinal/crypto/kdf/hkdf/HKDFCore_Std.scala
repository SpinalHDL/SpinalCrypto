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
package spinal.crypto.kdf.hkdf

import spinal.core._
import spinal.crypto.hash.{HashCoreConfig, HashCoreIO}
import spinal.crypto.mac.hmac.{HMACCoreStdConfig, HMACCore_Std}
import spinal.lib._
import spinal.lib.fsm._


/**
  * HKDF
  *
  * https://tools.ietf.org/html/rfc5869#ref-HKDF-paper
  *
  */
class HKDFCore_Std(configHash: HashCoreConfig, sizeIKM: BitCount) extends Component {

  // config
  val useExtract = true
  val useSalt    = true
  val useInfo    = true


  val io = new Bundle{
    val hash = master(HashCoreIO(configHash))

    val init  = in Bool
    val valid = in Bool

    val ikm   = in Bits(sizeIKM )
    val salt  = in Bits(configHash.hashBlockWidth) default(0)

    val info  = in Bits(32  bits)
    val l     = in UInt(32  bits)
  }


  val extractEnable = RegInit(True)
  val cnt = Reg(UInt(32 bits))
  val msg = Reg(Bits(32 bits))


  val hmac = new HMACCore_Std(HMACCoreStdConfig(configHash.hashBlockWidth, configHash))
  hmac.io.hashCore <> io.hash

  hmac.io.hmacCore.cmd.valid := False
  hmac.io.hmacCore.init := False



  // !!!! can be remove if the input key is a good pseudorandom key !!!!
  /**
    * HKDF-Extract(salt, IKM) -> PRK
    *
    * Options:
    *   Hash     a hash function; HashLen denotes the length of the
    *   hash function output in octets
    *
    * Inputs:
    *   salt     optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
    *   IKM      input keying material
    *
    * Output:
    *   PRK      a pseudorandom key (of HashLen octets)
    *
    * The output PRK is calculated as follows:
    *
    *   PRK = HMAC-Hash(salt, IKM)
    */
  val extract = new Area{

    // round up the size of the message to get modulos 32
    val messageWidth = sizeIKM.value + (sizeIKM.value % 32)
    println(s"message width : ${messageWidth}")
    val message =  io.ikm ## B(0, messageWidth  - sizeIKM.value bits )

    val msgSplit = message.subdivideIn(32 bits).reverse

    val prk = Reg(Bits(configHash.hashWidth))

    when(extractEnable && hmac.io.hmacCore.rsp.valid){
      prk := hmac.io.hmacCore.rsp.hmac
    }

    val sm = new StateMachine{

      val sIdle: State = new State with EntryPoint {
        whenIsActive{
          when(io.init){
            hmac.io.hmacCore.init := True
          }
          when(io.valid){
            cnt := 0
            goto(sStart)
          }
        }
      }

      val sStart: State = new State{
        whenIsActive{
          msg := msgSplit(cnt.resized)

          when(cnt === (messageWidth / 32)){
            goto(sEnd)
          }otherwise {
            goto(sSend)
          }
        }
      }

      val sSend: State = new State{
        whenIsActive{
          hmac.io.hmacCore.cmd.valid := True
          when(hmac.io.hmacCore.cmd.ready){
            cnt := cnt + 1
            goto(sStart)
          }
        }
      }

      val sEnd: State = new State{
        whenIsActive{
          extractEnable := False
          when(io.init){
            goto(sIdle)
          }
        }
      }
    }

  }


  /**
    * * 2.3.  Step 2: Expand
    * *
    * * HKDF-Expand(PRK, info, L) -> OKM
    * *
    * * Options:
    * * Hash     a hash function; HashLen denotes the length of the
    * * hash function output in octets
    * *
    * *
    * * Inputs:
    * * PRK      a pseudorandom key of at least HashLen octets
    * * (usually, the output from the extract step)
    * * info     optional context and application specific information
    * * (can be a zero-length string)
    * * L        length of output keying material in octets
    * * (<= 255*HashLen)
    * *
    * * Output:
    * * OKM      output keying material (of L octets)
    * *
    * * The output OKM is calculated as follows:
    * *
    * * N = ceil(L/HashLen)
    * * T = T(1) | T(2) | T(3) | ... | T(N)
    * * OKM = first L octets of T
    * *
    * * where:
    * * T(0) = empty string (zero length)
    * * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    * * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    * * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    * * ...
    * *
    * * (where the constant concatenated to the end of each T(n) is a
    * * single octet.)
    */
  val expand = new Area{

    val t   = Reg(Bits(256 bits)) init(0)



  }


  hmac.io.hmacCore.cmd.key  := (extractEnable) ? io.salt | extract.prk.resized
  hmac.io.hmacCore.cmd.size := (cnt === ((extract.messageWidth / 32) - 1)) ? U(1, 2 bits) | U(0, 2 bits)
  hmac.io.hmacCore.cmd.msg  := msg
  hmac.io.hmacCore.cmd.last := cnt === (extract.messageWidth / 32) - 1
}