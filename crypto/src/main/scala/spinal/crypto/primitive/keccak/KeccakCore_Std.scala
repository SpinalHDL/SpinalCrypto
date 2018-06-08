package spinal.crypto.primitive.keccak

import spinal.core._

class KeccakCore_Std extends Component {

  val io = new Bundle {

  }

  val stateA = out(Vec(Vec(Bits(32 bits), 5), 5))
  val stateB = in(Vec(Vec(Bits(32 bits), 5), 5))


//  # θ step
//    C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
//  D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
//  A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)


  /**
    * Chi - X
    *
    * A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    */
  for(y <- 0 to 4 ; x <- 0 to 4){
    stateA(x)(y) := stateB(x)(y) ^ (~stateB((x + 1) % 5)(y) & stateB((x + 2) % 5)(y))
  }

}


object PlayWithKeccakCore extends App{
  SpinalVhdl(new KeccakCore_Std)
}
