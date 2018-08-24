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
package spinal.crypto.hash.sha2

import spinal.core._
import spinal.lib._
import spinal.crypto.hash._
import spinal.crypto.padding.{HashPadding_Config, HashPadding_Std}



/**
  * SHA2Core_Std component
  *
  * !!!!! SHA2 works in Big-Endian !!!!!!!
  *
  * SHA2 documentation :
  *   http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
  *   https://tools.ietf.org/html/rfc4634
  *   https://emn178.github.io/online-tools/sha512_256.html
  *
  */
class SHA2Core_Std(mode: SHA2_Type, dataWidth: BitCount = 32 bits) extends Component {

  val configCore =  HashCoreConfig(
    dataWidth      = dataWidth,
    hashWidth      = mode.hashWidth bits,
    hashBlockWidth = SHA2.blockWidth(mode) bits
  )

  val configPadding = HashPadding_Config(
    dataInWidth  = dataWidth ,
    dataOutWidth = SHA2.blockWidth(mode) bits,
    endianess    = BIG_endian
  )

  val io = slave(HashCoreIO(configCore))

  val engine  = new SHA2Engine_Std(mode)
  val padding = new HashPadding_Std(configPadding)

  // Connect IO <-> padding
  padding.io.init      := io.init
  padding.io.cmd.valid := io.cmd.valid
  padding.io.cmd.data  := io.cmd.msg
  padding.io.cmd.last  := io.cmd.last
  padding.io.cmd.size  := io.cmd.size

  io.cmd.ready := padding.io.cmd.ready

  // Connect padding <-> engine
  engine.io.cmd.valid   := padding.io.rsp.valid
  engine.io.cmd.message := padding.io.rsp.data

  padding.io.rsp.ready := engine.io.cmd.ready

  // Connect Engine <-> io
  io.rsp.valid   := engine.io.rsp.valid && io.cmd.last && io.cmd.ready
  io.rsp.digest  := engine.io.rsp.digest
  engine.io.init := io.init
}



/**
  * SHA-2 engine
  * Round : 64 or 80
  *
  *
  * Extension :
  *
  * Wt = M(i) , for t = 0 to 15
  * For t = 16 to nbrRound{
  *   Wt =  SSIG1(W(t-2)) + W(t-7) + SSIG0(W(t-15)) + W(t-16)
  * }
  *
  *     SSIG0(x) = (x ROR  7) ^ (x ROR 18) ^ (x SHR  3), for 224, 256
  *              = (x ROR  1) ^ (x ROR  8) ^ (x SHR  7), for 384, 512
  *     SSIG1(x) = (x ROR 17) ^ (x ROR 19) ^ (x SHR 10), for 224, 256
  *              = (x ROR 19) ^ (x ROR 61) ^ (x SHR  6), for 384, 512
  *
  * Compression Function :
  *
  * One round for SHA-2
  *
  *    --- --- --- --- --- --- --- ---
  *   | A | B | C | D | E | F | G | H |------------
  *    --- --- --- --- --- --- --- ---             |
  *     |   |   |   |   |   |   |       _____      |       Wt
  *     |   |   |   |   |--------------|     |     |       |
  *     |   |   |   |   |   |----------|  CH |---> + <---- + <--- Kt
  *     |   |   |   |   |   |   |------|_____|     |
  *     |   |   |   |   |   |   |      _______     |
  *     |   |   |   |-----------------|_BSIG1_|--> +
  *     |   |   |   |   |   |   |                  |
  *     |   |   |   + <----------------------------|      CH    = (E and F) xor (~E and G)
  *     |   |   |   |   |   |   |      ____        |      MA    = (A and B) xor (A and C) xor (B xor C)
  *     |-----------------------------|    |       |      BSIG0 = (A ROR  2) xor (A ROR 13) xor (A ROR 22), for 224, 256
  *     |   |-------------------------| Ma |-----> +            = (A ROR 28) xor (A ROR 34) xor (A ROR 39), for 384, 512
  *     |   |   |---------------------|___ |       |      BSIG1 = (E ROR  6) xor (E ROR 11) xor (E ROR 25), for 224, 256
  *     |   |   |   |   |   |   |     _______      |            = (E ROR 14) xor (E ROR 18) xor (E ROR 41), for 384, 512
  *     |----------------------------|_BSIG0_|---> +
  *     |   |   |   |   |   |   |                  |
  *     \   \   \   \   \   \   \                  |
  *      \   \   \   \   \   \   \                 |
  *       \   \   \   \   \   \   \                |
  *        \   \   \   \   \   \   \               |
  *    --- --- --- --- --- --- --- ---             |
  *   | A | B | C | D | E | F | G | H |            |
  *    --- --- --- --- --- --- --- ---             |
  *     |_________________________________________/
  *
  *
  */
class SHA2Engine_Std(mode: SHA2_Type) extends Component {

  /** IO */
  val io = slave(HashEngineIO(SHA2.blockWidth(mode) bits, mode.hashWidth bits))


  /** Internal variables */
  val a, b, c, d, e, f, g, h = Reg(UInt(SHA2.variableWidth(mode) bits))

  val w = Vec(Reg(UInt(SHA2.variableWidth(mode) bits)), SHA2.numberRound(mode))

  val roundCnt         = Reg(UInt(log2Up(SHA2.numberRound(mode)) bits))
  val startProcessing  = RegInit(False)
  val finalProcessing  = RegInit(False)
  val isBusy           = RegInit(False)

  val memK = Mem(UInt(SHA2.variableWidth(mode) bits), SHA2.K(mode).map(U(_, SHA2.variableWidth(mode) bits)))
  val hash = Reg(Vec(UInt(SHA2.variableWidth(mode) bits), SHA2.InitHash(mode).length))

  val initHashValue = Vec(SHA2.InitHash(mode).map(U(_, SHA2.variableWidth(mode) bits)))

  /**
    * Command received
    */
  when(io.cmd.valid && !isBusy && !io.cmd.ready){

    for(i <- 0 until 16){
      w(i) := io.cmd.message.subdivideIn(SHA2.variableWidth(mode) bits).reverse(i).asUInt
    }

    a := hash(0)
    b := hash(1)
    c := hash(2)
    d := hash(3)
    e := hash(4)
    f := hash(5)
    g := hash(6)
    h := hash(7)

    startProcessing := True
    isBusy          := True
    roundCnt        := 0
  }

  /**
    * Init register
    */
  val initProcess = new Area {

    when(io.init){

      hash := initHashValue

      finalProcessing := False
      startProcessing := False
    }
  }


  /**
    * Processing message
    */
  val processing = new Area {

    when(startProcessing){

      when(roundCnt === SHA2.numberRound(mode) - 1){
        startProcessing := False
        finalProcessing := True
      }

      when(roundCnt < (SHA2.numberRound(mode) - 16)){
        w(roundCnt + 16) := w(roundCnt) + w(roundCnt + 9) + SHA2.SSIG0(w(roundCnt +  1), mode) + SHA2.SSIG1(w(roundCnt + 14), mode)
      }

      roundCnt := roundCnt + 1

      val temp1 = h + SHA2.BSIG1(e, mode) + SHA2.CH(e, f, g) + memK(roundCnt) + w(roundCnt)

      a := SHA2.BSIG0(a, mode) + SHA2.MAJ(a, b, c) + temp1
      b := a
      c := b
      d := c
      e := d + temp1
      f := e
      g := f
      h := g
    }


    /**
      * Compute intermediate hash value
      */
    when(finalProcessing){
      hash(0) := hash(0) + a
      hash(1) := hash(1) + b
      hash(2) := hash(2) + c
      hash(3) := hash(3) + d
      hash(4) := hash(4) + e
      hash(5) := hash(5) + f
      hash(6) := hash(6) + g
      hash(7) := hash(7) + h

      finalProcessing := False
      isBusy          := False
    }
  }

  io.rsp.valid  := RegNext(finalProcessing, False)
  io.rsp.digest := (mode match {
    case SHA2_256 | SHA2_512 => hash.reverse.asBits
    case SHA2_224                    => hash.dropRight(1).reverse.asBits // remove H
    case SHA2_384                    => hash.dropRight(2).reverse.asBits // remove G H
    case SHA2_512_224 | SHA2_512_256 => hash.reverse.asBits.resizeLeft(mode.hashWidth)
    case _                           => SpinalError(s"SHA-2 doesn't support the following hash size ${mode.hashWidth} bits")
  })

  io.cmd.ready  := io.rsp.valid
}
