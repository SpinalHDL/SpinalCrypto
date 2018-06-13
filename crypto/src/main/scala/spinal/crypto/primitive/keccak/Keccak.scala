package spinal.crypto.primitive.keccak

object Keccak {


  /**
    * Keccak-f[b], b = 25 * 2^l, l = 0 to 6 ===> (b = {25,50,100,200,400,800,1600})
    *
    *
    * sate a = a[5][5][w], w = 2^l ==> w = {1,2,4,8,16,32,64} and b=25w
    * nr = 12 + 2l
    *
    * sponge function = Keccak[r,c] =>> c = capacity, r = bitrate
    *
    *
    * e.g.
      Keccak-f[b](A) {
        for i in 0…n-1
          A = Round[b](A, RC[i])
        return A
      }

      Round[b](A,RC) {
        # θ step
        C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
        D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
        A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)

        # ρ and π steps
        B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)

        # χ step
        A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)

        # ι step
        A[0,0] = A[0,0] xor RC

        return A
      }


    Keccak[r,c](Mbytes || Mbits) {
      # Padding
      d = 2^|Mbits| + sum for i=0..|Mbits|-1 of 2^i*Mbits[i]
      P = Mbytes || d || 0x00 || … || 0x00
      P = P xor (0x00 || … || 0x00 || 0x80)

      # Initialization
      S[x,y] = 0,                               for (x,y) in (0…4,0…4)

      # Absorbing phase
      for each block Pi in P
        S[x,y] = S[x,y] xor Pi[x+5*y],          for (x,y) such that x+5*y < r/w
        S = Keccak-f[r+c](S)

      # Squeezing phase
      Z = empty string
      while output is requested
        Z = Z || S[x,y],                        for (x,y) such that x+5*y < r/w
        S = Keccak-f[r+c](S)

      return Z
    }


*/


  /**
    * The rotation offsets r[x,y]
    */
  private var pRawOffset : Map[(Int, Int), Int] = Map((0,0) -> 0)


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
