package ref.hash

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3


object SHA3 {
  def digest(sizeSha: Int)(inputString: String): Array[Byte] = {

    val sha3 = new DigestSHA3(sizeSha)
    sha3.update(inputString.getBytes("UTF-8"))

    return sha3.digest()
  }
}

object PlayWithSHA3 extends App {

  def bigIntToHex(value: Array[Byte]): String = s"0x${value.map(b => f"${b}%02X").mkString("")}"

  println(bigIntToHex(SHA3.digest(512)("A")))
}