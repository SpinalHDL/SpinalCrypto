package spinal.crypto.primitive.keccak

object Keccak_f {


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

    ----------------------------------------

    The round constants RC[i] are given in the table below for the maximum lane size 64. For smaller sizes, they are simply truncated. The formula can be found in the reference specifications.


RC[0]	0x0000000000000001	RC[12]	0x000000008000808B
RC[1]	0x0000000000008082	RC[13]	0x800000000000008B
RC[2]	0x800000000000808A	RC[14]	0x8000000000008089
RC[3]	0x8000000080008000	RC[15]	0x8000000000008003
RC[4]	0x000000000000808B	RC[16]	0x8000000000008002
RC[5]	0x0000000080000001	RC[17]	0x8000000000000080
RC[6]	0x8000000080008081	RC[18]	0x000000000000800A
RC[7]	0x8000000000008009	RC[19]	0x800000008000000A
RC[8]	0x000000000000008A	RC[20]	0x8000000080008081
RC[9]	0x0000000000000088	RC[21]	0x8000000000008080
RC[10]	0x0000000080008009	RC[22]	0x0000000080000001
RC[11]	0x000000008000000A	RC[23]	0x8000000080008008
Table 1: The round constants RC[i]

    ----------------------------------------

  The rotation offsets r[x,y] are given in the table below. The formula can be found in the reference specifications.

*/

  /**
    * Rotation offsets
    *           x = 3	  x = 4	  x = 0	  x = 1  	x = 2
    *  y = 2	   25	     39	      3	     10	     43
    *  y = 1	   55	     20	     36	     44	      6
    *  y = 0	   28  	   27	      0	      1	     62
    *  y = 4	   56	     14	     18	      2	     61
    *  y = 3	   21	      8 	   41	     45	     15
    */
  def offsetRotation : List[List[Int]] = List(
    List( 0, 36,  3, 41, 18),
    List( 1, 44, 10, 45,  2),
    List(62,  6, 43, 15, 61),
    List(28, 55, 25, 21, 56),
    List(27, 20, 39,  8, 14)
  )

  def RC : List[BigInt] = List(
    BigInt("0000000000000001", 16), BigInt("0000000000008082", 16),
    BigInt("800000000000808A", 16), BigInt("8000000080008000", 16),
    BigInt("000000000000808B", 16), BigInt("0000000080000001", 16),
    BigInt("8000000080008081", 16), BigInt("8000000000008009", 16),
    BigInt("000000000000008A", 16), BigInt("0000000000000088", 16),
    BigInt("0000000080008009", 16), BigInt("000000008000808B", 16),
    BigInt("800000000000008B", 16), BigInt("8000000000008089", 16),
    BigInt("8000000000008003", 16), BigInt("8000000000008002", 16),
    BigInt("8000000000000080", 16), BigInt("000000000000800A", 16),
    BigInt("800000008000000A", 16), BigInt("8000000080008081", 16),
    BigInt("8000000000008080", 16), BigInt("0000000080000001", 16)
  )

}
