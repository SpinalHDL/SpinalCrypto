package spinal.crypto.primitive.keccak

import spinal.core._
import spinal.lib._


case class KeccakCore_Std() extends Component {

}




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

case class KeccakCmdF_Std(width: Int) extends Bundle {
  val string = Bits(width bits)
}

case class KeccakRspF_Std(width: Int) extends Bundle {
  val string = Bits(width bits)
}

case class KeccakIOF_Std(width: Int) extends Bundle with IMasterSlave {
  val cmd = Stream(KeccakCmdF_Std(width))
  val rsp = Flow(KeccakRspF_Std(width))

  override def asMaster(): Unit = {
    slave(rsp)
    master(cmd)
  }
}


/**
  * KECCAK-f[b] = KECCAK-p[b, 12+2l].
  *
  */
class KeccakF_Std(b: Int) extends Component {

  assert(List(25, 50, 100, 200, 400, 800, 1600).contains(b))

  val io = slave(KeccakIOF_Std(b))

  /**
    * Compute number of round
    */
  val nr = 12 + 2 * log2Up(b / 25)


  /**
    * Instantiate the core
    */
  val core = new KeccakP_Std(b, nr)

  core.io <> io
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/**
  * KECCAK-p[b, nr]
  *
  *     1. Convert S into a state array
  *     2. For ir from 12+2l–nr to 12+2l –1, let A=Rnd(A, ir).
  *     3. Convert A into a string
  */
class KeccakP_Std(b: Int, nr: Int) extends Component {

  val w = b / 25

  val io = slave(KeccakIOF_Std(b))

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
      val index = (io.cmd.string.getWidth - 1) - w * (5 * y + x)
      state(x)(y) :=  io.cmd.string(index downto index - w + 1)
    }
    start := True
    rnd   := 0
  }

  /**
    * Execute Round
    */
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


  /**
    * Convert state to string
    */
  io.rsp.string := (for(y <- 0 to 4 ; x <- 0 to 4) yield permCore.io.rsp.state(x)(y)).reduce(_ ## _)
}




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


case class KeccakCmdRnd_Std(widthState: Int, widthCtnRound: Int) extends Bundle {
  val state = Vec(Vec(Bits(widthState bits), 5), 5)
  val rnd   = UInt(widthCtnRound bits)
}

case class KeccakRspRnd_Std(widthState: Int) extends Bundle {
  val state = Vec(Vec(Bits(widthState bits), 5), 5)
}

case class KeccakIORnd_Std(widthState: Int, widthCtnRound: Int) extends Bundle with IMasterSlave {
  val cmd = Stream(KeccakCmdRnd_Std(widthState, widthCtnRound))
  val rsp = Flow(KeccakRspRnd_Std(widthState))

  override def asMaster(): Unit = {
    slave(rsp)
    master(cmd)
  }
}


/**
  * The five step mappings that comprise a round of KECCAK-p[b, nr] are denoted by θ, ρ, π, χ, and ι.
  */
class KeccakRnd_Std(b: Int, nr: Int) extends Component {

  val w = b / 25

  /**
    * IO
    */
  val io = slave(KeccakIORnd_Std(w, log2Up(nr)))

  /**
    * Implement the state machine
    */
  val sm = new Area{

    val cnt   = Reg(UInt(2 bits))
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


object PlayWithKeccakCore extends App{
  //SpinalVhdl(new KeccakRnd_Std)
  //SpinalVhdl(new KeccakP_Std(1600, 24))
  SpinalVhdl(new KeccakF_Std(1600))
}
