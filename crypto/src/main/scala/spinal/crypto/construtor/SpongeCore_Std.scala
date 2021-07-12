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
package spinal.crypto.construtor

import spinal.core._
import spinal.crypto.primitive.keccak.{FuncIO_Std}
import spinal.lib._



case class SpongeCoreCmd_Std(width: Int) extends Bundle {
  val n = Bits(width bits)
}

case class SpongeCoreRsp_Std(width: Int) extends Bundle {
  val z = Bits(width bits)
}


/**
  * SPONGE[f, pad, r](N,d).
  * where f   = function on fixed-length string
  *       pad = padding rule
  *       r   = rate
  *       N   = bit string
  *       d   = bit length of the output string
  *
  *
  *       The rate r is a positive integer that is strictly less than the width b. The capacity, denoted by c, is
  * the positive integer b+r. Thus, r + c = b.
  *
  *       N                            Absorbing | Squeezing                           Z
  *       |                                      |                                     |
  *      PAD(*)------------ ...  ----\           |  /------- ... ------------------> TRUNC
  *       __     |     ___           |     ___   |  |   ___         |   ___   |
  *      |  |    |    |   |          |    |   |  |  |  |   |        |  |   |  |
  *  (r) |  | - XOR ->|   |       - XOR ->|   |--|---->|   |      ---->|   |---->
  *      |__|         | f | ....          | f |  |     | f | ...       | f |
  *      |  |         |   |               |   |  |     |   |           |   |
  *  (c) |  | ------->|   |       ------->|   |--|---->|   |      ---->|   |---->
  *      |__|         |___|               |___|  |     |___|           |___|
  *
  *    (*) the padding is done outside of this component
  */
class SpongeCore_Std(capacity: Int, rate: Int, d: Int) extends Component {

  val b          = capacity + rate
  val nbrSqueeze = scala.math.floor(d / rate.toDouble).toInt

  /**
    * IO
    */
  val io = new Bundle {
    val init   = in Bool()
    val cmd    = slave(Stream(Fragment(SpongeCoreCmd_Std(rate))))
    val rsp    = master(Flow(SpongeCoreRsp_Std(d)))
    val func   = master(FuncIO_Std(b, b))
  }

  val rReg = Reg(Bits(rate bits))
  val cReg = Reg(Bits(capacity bits))
  val zReg = if(nbrSqueeze != 0) Reg(Bits(rate * (nbrSqueeze + 1) bits)) else null

  val isProcessing = RegInit(False)
  val isSqueezing  = RegInit(False)
  val cntSqueeze   = if(nbrSqueeze != 0) Reg(UInt(log2Up(nbrSqueeze + 1) bits)) else null
  val saveInR      = if(nbrSqueeze != 0) False else null

  // Cmd func component
  io.func.cmd.valid   := isProcessing
  io.func.cmd.payload := (isSqueezing ? rReg | (io.cmd.n ^ rReg)) ## cReg

  // Rsp sponge
  val spg_rspValid = False
  val spg_cmdReady = False

  io.rsp.valid := RegNext(spg_rspValid, False)
  io.cmd.ready := RegNext(spg_cmdReady, False)
  io.rsp.z     := (if(nbrSqueeze != 0) zReg else rReg).resizeLeft(d)


  /**
    * Save func.rsp.data in rReg
    */
  if(nbrSqueeze != 0){
    when(saveInR){
      zReg.subdivideIn(rate bits).reverse(cntSqueeze.resized) := io.func.rsp.payload.resizeLeft(rate)
    }
  }


  /**
    * init
    */
  when(io.init){
    rReg := 0
    cReg := 0
    isSqueezing  := False
    isProcessing := False
    if(nbrSqueeze != 0) cntSqueeze := 0
  }


  /**
    * Start processing
    */
  when(io.cmd.valid && !io.cmd.ready && !isProcessing){
    isProcessing  := True
  }


  /**
    * Wait response of the function
    */
  when(io.func.rsp.valid){

    // Store the response
    rReg  := io.func.rsp.payload(b - 1        downto capacity)
    cReg  := io.func.rsp.payload(capacity - 1 downto 0)

    /**
      * Squeezing
      */
    if(nbrSqueeze != 0){

      when(isSqueezing){

        cntSqueeze := cntSqueeze + 1
        saveInR    := True

        when(cntSqueeze === nbrSqueeze ){
          isSqueezing  := False
          isProcessing := False
          spg_rspValid := True
          spg_cmdReady := True
        }
      }
    }

    /**
      * Absorbing
      */
    when(!isSqueezing){

      if(nbrSqueeze == 0){
        spg_rspValid := io.cmd.last
        spg_cmdReady := True
        isProcessing := False
      }else{
        spg_cmdReady := !io.cmd.last
        isProcessing := io.cmd.last
        isSqueezing  := io.cmd.last
        saveInR      := io.cmd.last
        when(io.cmd.last){
          cntSqueeze := cntSqueeze + 1
        }
      }
    }
  }
}


