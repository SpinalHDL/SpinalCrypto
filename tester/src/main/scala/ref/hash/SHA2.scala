package ref.hash


import java.security.MessageDigest


object SHA2 {
  def digest_256( inputString: String): Array[Byte] = {

    val md = MessageDigest.getInstance("SHA-256")
    md.update(inputString.getBytes())

    val digest = md.digest()

    return digest
  }

  def digest_512( inputString: String): Array[Byte] = {

    val md = MessageDigest.getInstance("SHA-512")
    md.update(inputString.getBytes())

    val digest = md.digest()

    return digest
  }
}


object PlayWithSHA2 extends App {

  def bigIntToHex(value: Array[Byte]): String = s"0x${value.map(b => f"${b}%02X").mkString("")}"

  println(bigIntToHex(SHA2.digest_256("abc")))
}

