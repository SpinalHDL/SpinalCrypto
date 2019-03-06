package ref.symmetric

import java.security.SecureRandom


object Twofish {

  /**
    * Cast the input array to x byte
    */
  private def castByteArray(input: Array[Byte], castSize: Int): Array[Byte] = {
    if(input.length == castSize){
      input
    }else if(input.length > castSize){
      input.takeRight(castSize)
    }else{
      Array.fill[Byte](castSize - input.length)(0x00) ++ input
    }
  }

  def main(args: Array[String]): Unit = {

    val plainText = Array(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00, 0x00,0x00, 0x00, 0x00, 0x00)
    val key       = Array(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00, 0x00,0x00, 0x00, 0x00, 0x00)

    val encrypted = RefTwoFish.encrypt(plainText, key, false);
    //
    println("Encrypted:");
    for(d <- encrypted) print(f"$d%X ")
  }
}





/**
 * @author sala
 */
object RefTwoFish {
    val RS = List(
            List(0x01.toByte, 0xA4.toByte, 0x55.toByte, 0x87.toByte, 0x5A.toByte, 0x58.toByte, 0xDB.toByte, 0x9E.toByte),
            List(0xA4.toByte, 0x56.toByte, 0x82.toByte, 0xF3.toByte, 0x1E.toByte, 0xC6.toByte, 0x68.toByte, 0xE5.toByte),
            List(0x02.toByte, 0xA1.toByte, 0xFC.toByte, 0xC1.toByte, 0x47.toByte, 0xAE.toByte, 0x3D.toByte, 0x19.toByte),
            List(0xA4.toByte, 0x55.toByte, 0x87.toByte, 0x5A.toByte, 0x58.toByte, 0xDB.toByte, 0x9E.toByte, 0x03.toByte)
    )

    val MDS = List(
            List( 0x01.toByte, 0xEF.toByte, 0x5B.toByte, 0x5B.toByte),
            List( 0x5B.toByte, 0xEF.toByte, 0xEF.toByte, 0x01.toByte),
            List( 0xEF.toByte, 0x5B.toByte, 0x01.toByte, 0xEF.toByte),
            List( 0xEF.toByte, 0x01.toByte, 0xEF.toByte, 0x5B.toByte)
    )

    val t00 = List( 0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4)
    val t01 = List( 0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD)
    val t02 = List( 0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1)
    val t03 = List( 0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA)

    //
    val t10 = List( 0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5 )
    val t11 = List( 0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8 )
    val t12 = List( 0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF )
    val t13 = List( 0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA )


    def encrypt(plainText: Array[Int], key: Array[Int], debug: Boolean) : Array[Int] = {
        val roundKey01 = roundKeys(key, 0)
        val roundKey23 = roundKeys(key, 1)
        val roundKey45 = roundKeys(key, 2)
        val roundKey67 = roundKeys(key, 3)

        // whitening
        var whitened = whitening(plainText, roundKey01(0), roundKey01(1), roundKey23(0), roundKey23(1))

        for(i <- 0 until 16){

            whitened = encryptionRound(whitened, key, i);

            whitened = Array(whitened(2), whitened(3), whitened(0), whitened(1))

        }
        // Swapping
        whitened = Array(whitened(2), whitened(3), whitened(0), whitened(1)) 
        whitened = whitening(whitened, roundKey45(0), roundKey45(1), roundKey67(0), roundKey67(1))
        return whitened
    }




 /*
    def decrypt( cypheredText : Array[Int],  key : Array[Int], debug: Boolean) : Array[Int] = {

        val roundKey01 = roundKeys(key, 0)
        val roundKey23 = roundKeys(key, 1)
        val roundKey45 = roundKeys(key, 2)
        val roundKey67 = roundKeys(key, 3)

        // whitening
        val whitened = whitening(cypheredText, roundKey45[0], roundKey45[1], roundKey67[0], roundKey67[1]);




        //
        whitened = new int[] {whitened[2], whitened[3], whitened[0], whitened[1]};
        for(int i = 15; i >= 0; i--) {
            whitened = decryptionRound(whitened, key, i);
            if(debug) {
                System.out.println("R"+ (i + 1) + ":");
                if(i % 2 == 0) {
                    Utils.printInternal(whitened);
                }
            }
            whitened = new int[] {whitened[2], whitened[3], whitened[0], whitened[1]};
            if(debug && i % 2 != 0) {
                Utils.printInternal(whitened);
            }
        }
        whitened = whitening(whitened, roundKey01[0], roundKey01[1], roundKey23[0], roundKey23[1]);
        if(debug) {
        System.out.println("Whitened:");
        Utils.printInternal(whitened);
        }
        return whitened;

    }

  */

    def whitening(plainText: Array[Int], k0: Int, k1: Int, k2: Int, k3: Int) : Array[Int] = {
        return  Array(
                plainText(0) ^ k0,
                plainText(1) ^ k1,
                plainText(2) ^ k2,
                plainText(3) ^ k3
        )
    }

    def encryptionRound(input : Array[Int], key: Array[Int], round: Int) : Array[Int] = {
        val s = getS(key)
        val t0 = h(input(0),                        s(1), s(0))
        val t1 = h(Integer.rotateLeft(input(1), 8), s(1), s(0))
        val pPht = pht(t0, t1)
        val roundKeys2r_8_2r_9 = roundKeys(key, round + 4)
        //
        val f0 = pPht(0) + roundKeys2r_8_2r_9(0)
        val f1 = pPht(1) + roundKeys2r_8_2r_9(1)
        //
        val c2 = Integer.rotateRight((f0 ^ input(2)), 1)
        val c3 = (f1 ^ Integer.rotateLeft(input(3), 1))
        //
        return Array(input(0), input(1), c2, c3 )
    }
     /*
    public static int[] decryptionRound(int[] input, int[] key, int round) {
        final int[] s = getS(key);
        int t0 = h(input[2],                        s[1], s[0]);
        int t1 = h(Integer.rotateLeft(input[3], 8), s[1], s[0]);
        final int[] pPht = pht(t0, t1);
        final int[] roundKeys = roundKeys(key, round + 4);
        //
        final int f0 = pPht[0] + roundKeys[0];
        final int f1 = pPht[1] + roundKeys[1];
        //
        final int p2 = Integer.rotateLeft(input[0], 1) ^ f0;
        final int p3 = Integer.rotateRight(input[1] ^ f1, 1);
        //
        return new int[] {  p2, p3, input[2], input[3]};

    }
  */

    def pht(a: Int, b: Int) : Array[Int] = {
        val a1 = a + b
        val b1 = (a + 2 * b)
        return  Array(a1, b1)
    }

    def h(input:Int,  l0: Int, l1: Int) : Int = {
        val galua256 = new Galua256(Integer.parseInt("01101001", 2).toByte)
        val x = asBytes(input)
        val y = asBytes(l1)
        val z = asBytes(l0)
        val input11 = Array(
            q1((q0( (q0(x(0)) ^ y(0)).toByte) ^ z(0)).toByte),
            q0((q0( (q1(x(1)) ^ y(1)).toByte) ^ z(1)).toByte),
            q1((q1( (q0(x(2)) ^ y(2)).toByte) ^ z(2)).toByte),
            q0((q1( (q1(x(3)) ^ y(3)).toByte) ^ z(3)).toByte)
        )
        val multiplication = multiply(galua256, MDS, input11)
        return fromBytes(multiplication)
    }


    def q0(input: Byte): Byte = {
        val a0 = ((input >> 4) & 0xF).toByte
        val b0 = (input & 0xF).toByte
        val a1 = (a0 ^ b0).toByte
        val b1 = (a0 ^ ((b0 & 1) << 3 | b0 >> 1) ^ ((8*a0) & 0xF)).toByte
        val a2 = t00(a1)
        val b2 = t01(b1)
        val a3 = (a2 ^ b2).toByte
        val b3 = (a2 ^ ((b2 & 1) << 3 | b2 >> 1) ^ ((8*a2) & 0xF)).toByte
        val a4 = t02(a3)
        val b4 = t03(b3)
        val result = ((b4 << 4) | a4).toByte
      return result
    }

    def q1(input : Byte) : Byte = {
        val a0 = ((input >> 4) & 0xF).toByte
        val b0 = (input & 0xF).toByte
        val a1 = (a0 ^ b0).toByte
        val b1 = (a0 ^ ((b0 & 1) << 3 | b0 >> 1) ^ ((8*a0) & 0xF)).toByte
        val a2 = t10(a1)
        val b2 = t11(b1)
        val a3 = (a2 ^ b2).toByte
        val b3 = (a2 ^ ((b2 & 1) << 3 | b2 >> 1) ^ ((8*a2) & 0xF)).toByte
        val a4 = t12(a3)
        val b4 = t13(b3)
        val result = ((b4 << 4) | a4).toByte
      return result
    }

    def getS(key : Array[Int]) : Array[Int] = {
        val m0 = key(0)
        val m1 = key(1)
        val m2 = key(2)
        val m3 = key(3)

        val S0 = compute_RS(m0, m1)
        val S1 = compute_RS(m2, m3)

        return Array ( S0, S1)
    }

    def compute_RS( X: Int, Y: Int) : Int ={
        val x = asBytes(X)
        val y = asBytes(Y)
        val XY = new Array[Byte](8)
        // Merging x and y
        System.arraycopy(x, 0, XY, 0, 4)
        System.arraycopy(y, 0, XY, 4, 4)
        //

        val galua = new Galua256(Integer.parseInt("01001101", 2).toByte)
        //
        val S = multiply(galua, RS, XY);
        return fromBytes(S);
    }

    def  multiply(galua: Galua256, matrix: List[List[Byte]], vector: Array[Byte]): Array[Byte] = {

      val S = new Array[Byte](vector.length)

      for(i <- 0 until matrix.length){
            val RSrow = matrix(i)
            S(i) = galua.multiply(RSrow(0), vector(0))
            for(j <- 1 until RSrow.length) {
                S(i) = galua.add(S(i), galua.multiply(RSrow(j), vector(j)));
            }
        }
        return S
    }

    def roundKeys(key: Array[Int], round: Int) : Array[Int] = {

        val m0 = key(0)
        val m1 = key(1)
        val m2 = key(2)
        val m3 = key(3)

        //
        val Me = Array (m0, m2)
        val Mo = Array (m1, m3)
        //
        val rho   = (1 << 24) | (1 << 16) | (1 << 8) | 1
        val Ai    = h(2 * round * rho, Me(0), Me(1))
        val Bi    = Integer.rotateLeft(h((2 * round + 1) * rho, Mo(0), Mo(1)), 8)
        val pPht  = pht(Ai, Bi)
        val K2i   = pPht(0)
        val K2i_1 = Integer.rotateLeft(pPht(1), 9)
        return Array( K2i, K2i_1)
    }

    def asBytes( intValue : Int): Array[Byte] = {
        return Array(
                (intValue).toByte,
                (intValue >>> 8) .toByte,
                (intValue >>> 16).toByte,
                (intValue >>> 24).toByte
        )
    }


    def fromBytes(bytes: Array[Byte]): Int = {
        var S0 = 0
        for(i <- 0 until 4) {
            S0 |= ((0xFF & bytes(i)) << (i * 8))
        }
        return S0
    }

}






class Galua256(mask: Byte) {


  def add(a: Byte, b: Byte): Byte = {
    return (a ^ b).toByte
  }
       /*
  public byte add(byte a, byte... b) {
    byte sum = a;
    for (byte aB : b) {
      sum = add(sum, aB);
    }
    return sum;
  }
     */
  def  multiply(a: Byte, b: Byte): Byte ={
    var p = 0.toByte
    var aTmp = a
    var bTmp = b

    for(i <- 0 until 8){
      if((bTmp & 1) != 0) {
        p = (p ^ aTmp).toByte
      }

      val carry = (aTmp & 0x80).toByte
      aTmp = (aTmp << 1).toByte
      if(carry != 0) {
        aTmp =  (aTmp ^ mask).toByte
      }
      bTmp =  (bTmp >> 1).toByte
    }
    return p
  }
}



/*
        int[] plainText = new int[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,0x07,0x08,0x09,0x0A, 0x0B,0x0C, 0x0D, 0x0E, 0x0F};//new int[] {0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C };
        int[] p = new int[4];
        for(int i = 0; i < 4; i++) {
            p[i] = plainText[4*i] + 256*plainText[4*i+1] + (plainText[4*i+2] << 16) + (plainText[4*i+3] << 24);
        }
        System.out.println("Input:");
        Utils.printInput(p);
        int[] key = p;
        System.out.println("Key:");
        Utils.printInput(key);
        //
        int[] encrypted = TwoFish.encrypt(p, key);
        //
        System.out.println("Encrypted:");
        Utils.printInput(encrypted);
        System.out.println();

        int[] decrypted = TwoFish.decrypt(encrypted, key);
        System.out.println("Decrypted:");
        Utils.printInput(decrypted);

 */
