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

import spinal.core._
import spinal.lib._



case class KeccakCmdF_Std(width: Int) extends Bundle {
  val string = Bits(width bits)
}

case class KeccakRspF_Std(width: Int) extends Bundle {
  val string = Bits(width bits)
}

case class FuncIO_Std(cmdWidth: Int, rspWidth: Int) extends Bundle with IMasterSlave {
  val cmd = Stream(Bits(cmdWidth bits))
  val rsp = Flow(Bits(rspWidth bits))

  override def asMaster(): Unit = {
    slave(rsp)
    master(cmd)
  }
}


/**
  * Keccak-f[b] = KECCAK-p[b, 12 + 2l], b = 25 * 2^l, l = 0 to 6 ===> (b = {25,50,100,200,400,800,1600})
  *
  * @note Keccak interprets byte arrays in big-endian, but with an LSB bit numbering.
  *
  * @param b    The width of a KECCAK-p permutation in bits
  */
class KeccakF_Std(b: Int) extends Component {

  assert(List(25, 50, 100, 200, 400, 800, 1600).contains(b))

  val io = slave(FuncIO_Std(b, b))

  /**
    * Compute number of round
    * nr = 12 + 2l
    */
  val nr = 12 + 2 * log2Up(b / 25)


  /** Instantiate the KeccakP core  */
  val core = new KeccakP_Std(b, nr)

  core.io <> io
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Keccak-P
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/**
  * KECCAK-p[b, nr]
  *
  *     1. Convert S into a state array
  *     2. For ir from 12+2l–nr to 12+2l –1, let A=Rnd(A, ir).
  *     3. Convert A into a string
  *
  * @param b    The width of a KECCAK-p permutation in bits
  * @param nr   The number of rounds for a KECCAK-p permutation
  */
class KeccakP_Std(b: Int, nr: Int) extends Component {

  // Compute the lane size of a KECCAK-p permutation in bits (state[5][5][w])
  val w = b / 25

  /** IO */
  val io = slave(FuncIO_Std(b, b))

  io.cmd.ready := False
  io.rsp.valid := False

  val start = RegInit(False)
  val rnd   = Reg(UInt(log2Up(nr) bits))

  val permCore = new KeccakRnd_Std(b, nr)

  permCore.io.cmd.valid := False
  permCore.io.cmd.rnd   := rnd
  permCore.io.cmd.state.map(_.map(_ := 0))


  /**
    * Convert string to state
    * A[x, y,z] = S[w(5y+x)+z].
    */
  val state = Reg(Vec(Vec(Bits(w bits), 5), 5))
  when(io.cmd.valid & !start){
    for(x <- 0 to 4 ; y <- 0 to 4 ){
      val index = (io.cmd.payload.getWidth - 1) - w * (5 * y + x)
      state(x)(y) :=  io.cmd.payload(index downto index - w + 1)
    }
    start := True
    rnd   := 0
  }

  /**
    * Controller
    */
  val ctrl = new Area{
    when(start){
      permCore.io.cmd.valid := True
      permCore.io.cmd.state := state
    }

    when(permCore.io.rsp.valid){
      state := permCore.io.rsp.state
      rnd   := rnd + 1

      when(rnd === nr - 1){
        io.cmd.ready := True
        start        := False
        io.rsp.valid := True
      }
    }
  }

  /**
    * Convert state to string
    */
  io.rsp.payload := (for(y <- 0 to 4 ; x <- 0 to 4) yield permCore.io.rsp.state(x)(y)).reduce(_ ## _)
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Keccak Round
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



case class KeccakCmdRnd_Std(widthState: Int, widthCtnRound: Int) extends Bundle {
  val state = Vec(Vec(Bits(widthState bits), 5), 5)
  val rnd   = UInt(widthCtnRound bits)
}

case class KeccakRspRnd_Std(widthState: Int) extends Bundle {
  val state = Vec(Vec(Bits(widthState bits), 5), 5)
}


/**
  * Round[b](A, RC) {
  *     # θ step
  *     C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
  *     D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
  *     A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
  *
  *     # ρ and π steps
  *     B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
  *
  *     # χ step
  *     A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
  *
  *     # ι step
  *     A[0,0] = A[0,0] xor RC
  *
  *     return A
  * }
  *
  * @param b    The width of a KECCAK-p permutation in bits
  * @param nr   The number of rounds for a KECCAK-p permutation
  */
class KeccakRnd_Std(b: Int, nr: Int) extends Component {

  // Compute the lane size of a KECCAK-p permutation in bits (state[5][5][w])
  val w = b / 25

  /** IO */
  val io = new Bundle {
    val cmd = slave  Stream(KeccakCmdRnd_Std(w, log2Up(nr)))
    val rsp = master Flow(KeccakRspRnd_Std(w))
  }

  /**
    * Controller
    */
  val sm = new Area{

    val cnt   = Reg(UInt(1 bits))
    val start = RegInit(False)

    when(io.cmd.valid & !start){
      cnt   := 0
      start := True
    }

    when(start){
      cnt := cnt + 1
    }

    io.cmd.ready := False
    io.rsp.valid := False

    when(start & cnt === 1){
      io.cmd.ready := True
      io.rsp.valid := True
      start        := False
    }
  }


  /**
    *  Théta - θ
    *
    *     C[x]    = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4]   for x in 0…4
    *     D[x]    = C[(x-1) mod 5] xor rot(C[(x+1) mod 5], 1)            for x in 0…4, (x-1 mod 5 == x+4 mod 5)
    *     A'[x,y] = A[x,y] xor D[x]                                      for (x,y) in (0…4,0…4)
    */
  val sTheta = Vec(Vec(Bits(w bits), 5), 5)

  val c = Vec(Bits(w bits), 5)
  val d = Vec(Bits(w bits), 5)

  for(x <- 0 to 4){
    c(x) := io.cmd.state(x).reduce(_ ^ _)
    d(x) := c((x + 4) % 5) ^ (c((x + 1) % 5)).rotateLeft(1)

    for(y <- 0 to 4){
      sTheta(x)(y) := io.cmd.state(x)(y) ^ d(x)
    }
  }


  /**
    * Rhô - ρ
    *
    *   A'[x,y] = rot(A[x,y], offset(x,y))
    */
  val sRho = Reg(Vec(Vec(Bits(w bits), 5), 5))

  for(x <- 0 to 4 ; y <- 0 to 4){
    sRho(x)(y) := sTheta(x)(y).rotateLeft(Keccak.pOffset(x, y, 64))
  }


  /**
    * Pi - π
    *
    *    A′[x, y] = A[(x + 3y) mod 5, x]    for (x,y) in (0…4,0…4)
    */
  val sPi = Vec(Vec(Bits(w bits), 5), 5)


  for(x <- 0 to 4 ; y <- 0 to 4){
    sPi(x)(y) := sRho((x + 3 * y) % 5)(x)
  }


  /**
    * Khi - χ
    *
    * A′[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    */
  val sKhi = Vec(Vec(Bits(w bits), 5), 5)

  for(y <- 0 to 4 ; x <- 0 to 4){
    sKhi(x)(y) := sPi(x)(y) ^ (~sPi((x + 1) % 5)(y) & sPi((x + 2) % 5)(y))
  }


  /**
    * Iota - ι
    *
    *  A′[0,0] = A[0,0] xor RC[rnd]
    */
  val sIota = Reg(Vec(Vec(Bits(w bits), 5), 5))
  val memRC = Mem(Bits(w bits), Keccak.RC.map(B(_, w bits)))

  sIota.allowOverride
  sIota       := sKhi
  sIota(0)(0) := sKhi(0)(0) ^ memRC(io.cmd.rnd)


  /**
    * Output the result
    */
  io.rsp.state  := sIota
}
