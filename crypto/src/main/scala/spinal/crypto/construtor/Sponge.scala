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
import spinal.crypto.primitive.keccak.{KeccakF_Std, KeccakIOF_Std}
import spinal.lib._

case class SpongeCmd_Std(width: Int) extends Bundle {
  val n = Bits(width bits)

}
case class SpongeRsp_Std(width: Int) extends Bundle {
  val z = Bits(width bits)
}
case class SpongeIO_Std(cmd_width: Int, rsp_width: Int) extends Bundle with IMasterSlave {
  val cmd  = Stream(Fragment(SpongeCmd_Std(cmd_width)))
  val rsp  = Flow(SpongeRsp_Std(rsp_width))
  val init = Bool

  override def asMaster(): Unit = {
    master(cmd)
    slave(rsp)
    out(init)
  }
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
  *      PAD -------------- ...  ----\           |  /------- ... ------------------> TRUNC
  *       __     |     ___           |     ___   |  |   ___         |   ___   |
  *      |  |    |    |   |          |    |   |  |  |  |   |        |  |   |  |
  *  (r) |  | - XOR ->|   |       - XOR ->|   |--|---->|   |      ---->|   |---->
  *      |__|         | f | ....          | f |  |     | f | ...       | f |
  *      |  |         |   |               |   |  |     |   |           |   |
  *  (c) |  | ------->|   |       ------->|   |--|---->|   |      ---->|   |---->
  *      |__|         |___|               |___|  |     |___|           |___|
  *                                              |
  */
class Sponge_Std(capacity: Int, rate: Int, d: Int ) extends Component {

  val b = capacity + rate
  val nbrSqueezingSeq = scala.math.ceil(d / rate.toDouble).toInt

  val io = new Bundle {
    val sponge = slave(SpongeIO_Std(rate, d))
    val func   = master(KeccakIOF_Std(b))
  }

  val rReg = Reg(Bits(rate bits))
  val cReg = Reg(Bits(capacity bits))
  val zReg = Reg(Bits(rate * nbrSqueezingSeq bits))

  val isProcessing = RegInit(False)
  val isSqueezing  = RegInit(False)
  val cntSqueezing = Reg(UInt(log2Up(nbrSqueezingSeq) + 1 bits))


  io.func.cmd.valid  := isSqueezing ? isSqueezing | isProcessing
  io.func.cmd.string := (isSqueezing ? rReg | (io.sponge.cmd.n ^ rReg)) ## cReg

  io.sponge.rsp.valid := False
  io.sponge.cmd.ready := False
  io.sponge.rsp.z     := zReg.resized

  /**
    * init
    */
  when(io.sponge.init){
    rReg := 0
    cReg := 0
    isSqueezing  := False
    cntSqueezing := 0
  }


  /**
    * Start processing
    */
  when(io.sponge.cmd.valid && !isProcessing){
    isProcessing := True
  }

  when(io.func.rsp.valid){

    rReg  := io.func.rsp.string(b - 1        downto capacity)
    cReg  := io.func.rsp.string(capacity - 1 downto 0)

    when(isSqueezing){                // Squeezing

      cntSqueezing := cntSqueezing + 1
      zReg.subdivideIn(rate bits)(cntSqueezing.resized) := io.func.rsp.string(b - 1 downto capacity)

      when(cntSqueezing >= nbrSqueezingSeq - 1){
        isSqueezing  := False
        isProcessing := False
        io.sponge.cmd.ready := True
        io.sponge.rsp.valid := True
      }

    }otherwise{                       // Absorbing
      isProcessing := io.sponge.cmd.last
      isSqueezing  := io.sponge.cmd.last
      io.sponge.cmd.ready := !io.sponge.cmd.last
    }
  }
}


object PlayWithSponge1 extends App{

  class TopLevel extends Component {
    val io = new Bundle{
      val sponge = slave(SpongeIO_Std(576, 512))
    }

    val sponge = new Sponge_Std(1024, 576, 512)
    val func   = new KeccakF_Std(1600)

    sponge.io.func <> func.io
    sponge.io.sponge <> io.sponge
  }

  SpinalVhdl(new TopLevel)
}
