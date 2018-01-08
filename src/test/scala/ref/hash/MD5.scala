package ref.hash

import java.security.MessageDigest


object MD5 {
  def digest( inputString: String): Array[Byte] = {

    val md = MessageDigest.getInstance("MD5")
    md.update(inputString.getBytes())

    val digest = md.digest()

    return digest
  }
}


object PlayWithMD5 extends App {

  def bigIntToHex(value: Array[Byte]): String = s"0x${value.map(b => f"${b}%02X").mkString("")}"

  println(bigIntToHex(MD5.digest("krayxcnxewqbnmjlwnyrgnejmwamalqqttcosijqxhsvxuusllllgcpzrygybspmpunptfdeihzbnuyseglbkuoxbzfnqgqxfea")))
}

