package spinal.crypto.hash.sha2

import spinal.core._

// http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
// https://tools.ietf.org/html/rfc4634

object Sha2CoreSpec {

  /**
    * Define Init hash value
    */

  def InitHash(hashSize: BitCount): List[BigInt] = hashSize.value match {
    case 224 => List(
      BigInt("c1059ed8", 16),
      BigInt("367cd507", 16),
      BigInt("3070dd17", 16),
      BigInt("f70e5939", 16),
      BigInt("ffc00b31", 16),
      BigInt("68581511", 16),
      BigInt("64f98fa7", 16),
      BigInt("befa4fa4", 16)
    )

    case 256 => List(
      BigInt("6a09e667", 16),
      BigInt("bb67ae85", 16),
      BigInt("3c6ef372", 16),
      BigInt("a54ff53a", 16),
      BigInt("510e527f", 16),
      BigInt("9b05688c", 16),
      BigInt("1f83d9ab", 16),
      BigInt("5be0cd19", 16)
    )

    case 384 => List(
      BigInt("cbbb9d5dc1059ed8", 16),
      BigInt("629a292a367cd507", 16),
      BigInt("9159015a3070dd17", 16),
      BigInt("152fecd8f70e5939", 16),
      BigInt("67332667ffc00b31", 16),
      BigInt("8eb44a8768581511", 16),
      BigInt("db0c2e0d64f98fa7", 16),
      BigInt("47b5481dbefa4fa4", 16)
    )

    case 512 => List(
      BigInt("6a09e667f3bcc908", 16),
      BigInt("bb67ae8584caa73b", 16),
      BigInt("3c6ef372fe94f82b", 16),
      BigInt("a54ff53a5f1d36f1", 16),
      BigInt("510e527fade682d1", 16),
      BigInt("9b05688c2b3e6c1f", 16),
      BigInt("1f83d9abfb41bd6b", 16),
      BigInt("5be0cd19137e2179", 16)
    )
    case _  => SpinalError(s"SHA-2 doesn't support the following hash size $hashSize")
  }


  /**
    *These words represent the first
   thirty-two bits of the fractional parts of the cube roots of the
   first sixty-four prime numbers
    */

  def K(hashSize: BitCount) = hashSize.value match {
    case 224 | 256 => List(
      BigInt("428a2f98", 16), BigInt("71374491", 16), BigInt("b5c0fbcf", 16), BigInt("e9b5dba5", 16), BigInt("3956c25b", 16), BigInt("59f111f1", 16), BigInt("923f82a4", 16), BigInt("ab1c5ed5", 16),
      BigInt("d807aa98", 16), BigInt("12835b01", 16), BigInt("243185be", 16), BigInt("550c7dc3", 16), BigInt("72be5d74", 16), BigInt("80deb1fe", 16), BigInt("9bdc06a7", 16), BigInt("c19bf174", 16),
      BigInt("e49b69c1", 16), BigInt("efbe4786", 16), BigInt("0fc19dc6", 16), BigInt("240ca1cc", 16), BigInt("2de92c6f", 16), BigInt("4a7484aa", 16), BigInt("5cb0a9dc", 16), BigInt("76f988da", 16),
      BigInt("983e5152", 16), BigInt("a831c66d", 16), BigInt("b00327c8", 16), BigInt("bf597fc7", 16), BigInt("c6e00bf3", 16), BigInt("d5a79147", 16), BigInt("06ca6351", 16), BigInt("14292967", 16),
      BigInt("27b70a85", 16), BigInt("2e1b2138", 16), BigInt("4d2c6dfc", 16), BigInt("53380d13", 16), BigInt("650a7354", 16), BigInt("766a0abb", 16), BigInt("81c2c92e", 16), BigInt("92722c85", 16),
      BigInt("a2bfe8a1", 16), BigInt("a81a664b", 16), BigInt("c24b8b70", 16), BigInt("c76c51a3", 16), BigInt("d192e819", 16), BigInt("d6990624", 16), BigInt("f40e3585", 16), BigInt("106aa070", 16),
      BigInt("19a4c116", 16), BigInt("1e376c08", 16), BigInt("2748774c", 16), BigInt("34b0bcb5", 16), BigInt("391c0cb3", 16), BigInt("4ed8aa4a", 16), BigInt("5b9cca4f", 16), BigInt("682e6ff3", 16),
      BigInt("748f82ee", 16), BigInt("78a5636f", 16), BigInt("84c87814", 16), BigInt("8cc70208", 16), BigInt("90befffa", 16), BigInt("a4506ceb", 16), BigInt("bef9a3f7", 16), BigInt("c67178f2", 16)
    )
    case 384 | 512 => List(
      BigInt("428a2f98d728ae22", 16), BigInt("7137449123ef65cd", 16), BigInt("b5c0fbcfec4d3b2f", 16), BigInt("e9b5dba58189dbbc", 16),
      BigInt("3956c25bf348b538", 16), BigInt("59f111f1b605d019", 16), BigInt("923f82a4af194f9b", 16), BigInt("ab1c5ed5da6d8118", 16),
      BigInt("d807aa98a3030242", 16), BigInt("12835b0145706fbe", 16), BigInt("243185be4ee4b28c", 16), BigInt("550c7dc3d5ffb4e2", 16),
      BigInt("72be5d74f27b896f", 16), BigInt("80deb1fe3b1696b1", 16), BigInt("9bdc06a725c71235", 16), BigInt("c19bf174cf692694", 16),
      BigInt("e49b69c19ef14ad2", 16), BigInt("efbe4786384f25e3", 16), BigInt("0fc19dc68b8cd5b5", 16), BigInt("240ca1cc77ac9c65", 16),
      BigInt("2de92c6f592b0275", 16), BigInt("4a7484aa6ea6e483", 16), BigInt("5cb0a9dcbd41fbd4", 16), BigInt("76f988da831153b5", 16),
      BigInt("983e5152ee66dfab", 16), BigInt("a831c66d2db43210", 16), BigInt("b00327c898fb213f", 16), BigInt("bf597fc7beef0ee4", 16),
      BigInt("c6e00bf33da88fc2", 16), BigInt("d5a79147930aa725", 16), BigInt("06ca6351e003826f", 16), BigInt("142929670a0e6e70", 16),
      BigInt("27b70a8546d22ffc", 16), BigInt("2e1b21385c26c926", 16), BigInt("4d2c6dfc5ac42aed", 16), BigInt("53380d139d95b3df", 16),
      BigInt("650a73548baf63de", 16), BigInt("766a0abb3c77b2a8", 16), BigInt("81c2c92e47edaee6", 16), BigInt("92722c851482353b", 16),
      BigInt("a2bfe8a14cf10364", 16), BigInt("a81a664bbc423001", 16), BigInt("c24b8b70d0f89791", 16), BigInt("c76c51a30654be30", 16),
      BigInt("d192e819d6ef5218", 16), BigInt("d69906245565a910", 16), BigInt("f40e35855771202a", 16), BigInt("106aa07032bbd1b8", 16),
      BigInt("19a4c116b8d2d0c8", 16), BigInt("1e376c085141ab53", 16), BigInt("2748774cdf8eeb99", 16), BigInt("34b0bcb5e19b48a8", 16),
      BigInt("391c0cb3c5c95a63", 16), BigInt("4ed8aa4ae3418acb", 16), BigInt("5b9cca4f7763e373", 16), BigInt("682e6ff3d6b2b8a3", 16),
      BigInt("748f82ee5defb2fc", 16), BigInt("78a5636f43172f60", 16), BigInt("84c87814a1f0ab72", 16), BigInt("8cc702081a6439ec", 16),
      BigInt("90befffa23631e28", 16), BigInt("a4506cebde82bde9", 16), BigInt("bef9a3f7b2c67915", 16), BigInt("c67178f2e372532b", 16),
      BigInt("ca273eceea26619c", 16), BigInt("d186b8c721c0c207", 16), BigInt("eada7dd6cde0eb1e", 16), BigInt("f57d4f7fee6ed178", 16),
      BigInt("06f067aa72176fba", 16), BigInt("0a637dc5a2c898a6", 16), BigInt("113f9804bef90dae", 16), BigInt("1b710b35131c471b", 16),
      BigInt("28db77f523047d84", 16), BigInt("32caab7b40c72493", 16), BigInt("3c9ebe0a15c9bebc", 16), BigInt("431d67c49c100d4c", 16),
      BigInt("4cc5d4becb3e42b6", 16), BigInt("597f299cfc657e2a", 16), BigInt("5fcb6fab3ad6faec", 16), BigInt("6c44198c4a475817", 16)
    )
    case _=> SpinalError(s"SHA-2 doesn't support the following hash size $hashSize")
  }


  /**
    * Fix logical function
    */
  def CH(x: UInt, y: UInt, z: UInt) = (x & y) ^ ((~x) & z)

  def MAJ(x: UInt, y: UInt, z: UInt) = (x & y) ^ (x & z) ^ (y & z)

  def BSIG0(x: UInt, hashSize: BitCount) = hashSize.value match {
    case 224 | 256 => x.rotateRight(2) ^ x.rotateRight(13) ^ x.rotateRight(22)
    case 384 | 512 => x.rotateRight(28) ^ x.rotateRight(34) ^ x.rotateRight(39)
    case _         => SpinalError(s"SHA-2 doesn't support the following hash size $hashSize")
  }

  def BSIG1(x: UInt, hashSize: BitCount) = hashSize.value match {
    case 224 | 256 => x.rotateRight(6) ^ x.rotateRight(11) ^ x.rotateRight(25)
    case 384 | 512 => x.rotateRight(14) ^ x.rotateRight(18) ^ x.rotateRight(41)
    case _         => SpinalError(s"SHA-2 doesn't support the following hash size $hashSize")
  }

  def SSIG0(x: UInt, hashSize: BitCount) = hashSize.value match {
    case 224 | 256 => x.rotateRight(7) ^ x.rotateRight(18) ^ x.rotateRight(3)
    case 384 | 512 => x.rotateRight(1) ^ x.rotateRight(8) ^ x.rotateRight(7)
    case _         => SpinalError(s"SHA-2 doesn't support the following hash size $hashSize")
  }

  def SSIG1(x: UInt, hashSize: BitCount) = hashSize.value match {
    case 224 | 256 => x.rotateRight(17) ^ x.rotateRight(19) ^ x.rotateRight(10)
    case 384 | 512 => x.rotateRight(19) ^ x.rotateRight(61) ^ x.rotateRight(6)
    case _         => SpinalError(s"SHA-2 doesn't support the following hash size $hashSize")
  }

}

