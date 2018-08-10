package ref.hash


import java.security.MessageDigest


object SHA2 {
  def digest(sha: String)(inputString: String): Array[Byte] = {

    val md = MessageDigest.getInstance(sha)
    md.update(inputString.getBytes())

    val digest = md.digest()

    return digest
  }
}


object PlayWithSHA2 extends App {

  def bigIntToHex(value: Array[Byte]): String = s"0x${value.map(b => f"${b}%02X").mkString("")}"

  println(bigIntToHex(SHA2.digest("SHA-256")("abc")))

}

