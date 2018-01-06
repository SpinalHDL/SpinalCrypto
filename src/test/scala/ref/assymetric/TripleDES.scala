package ref.assymetric



import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher



object TripleDES {

  /**
    * Encrypt/Decrypt a block
    */
  def block(verbose: Boolean)(key: BigInt, block: BigInt, enc: Boolean) = if(enc) encryptBlock(key, block, verbose) else decryptBlock(key, block, verbose)


  /**
    * Block Encryption
    */
  def encryptBlock(key: BigInt, block: BigInt, verbose: Boolean = false ): BigInt = {

    // Cast the input key
    val keyModified = castByteArray(key.toByteArray, 3 * 8)
    val myDesKey = new SecretKeySpec(keyModified, "DESede")

    // Create the cipher
    val desCipher = Cipher.getInstance("DESede/ECB/NoPadding")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.ENCRYPT_MODE, myDesKey)

    // cast input block
    val blockPlain = castByteArray(block.toByteArray, 8)

    // Encrypt the text
    val blockCipher = desCipher.doFinal(blockPlain)

    if(verbose){
      println(s"Plain  : 0x${blockPlain.map(b => "%02X".format(b)).mkString("")}")
      println(s"KEY    : 0x${myDesKey.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Cipher : 0x${blockCipher.map(b => "%02X".format(b)).mkString("")}")
      println("")
    }

    return BigInt(blockCipher.take(8))
  }


  /**
    * Block Decryption
    */
  def decryptBlock(key: BigInt, block: BigInt, verbose: Boolean = false ): BigInt = {

    // cast input key
    val keyModified = castByteArray(key.toByteArray, 3 * 8)

    val myDesKey = new SecretKeySpec(keyModified, "DESede")

    // Create the cipher
    val desCipher = Cipher.getInstance("DESede/ECB/NoPadding")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.DECRYPT_MODE, myDesKey)

    // cast input block
    val blockCipher = castByteArray(block.toByteArray, 8)

    // Encrypt the text

    val blockPlain = desCipher.doFinal(blockCipher)

    if(verbose){
      println(s"Cipher : 0x${blockCipher.map(b => "%02X".format(b)).mkString("")}")
      println(s"KEY    : 0x${myDesKey.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Plain  : 0x${blockPlain.map(b => "%02X".format(b)).mkString("")}")
      println("")
    }

    return BigInt(blockPlain.take(8))
  }

  /**
    * Cast the input array to x byte
    */
  private def castByteArray(input: Array[Byte], castSize: Int): Array[Byte] = {
    if(input.length == 8){
      input
    }else if(input.length > 8){
      input.takeRight(castSize)
    }else{
      Array.fill[Byte](castSize - input.length)(0x00) ++ input
    }
  }
}




object PlayWithRefTripleDES extends App{

  val cipher = TripleDES.encryptBlock(BigInt("2e8a66a77fc7decc352630923f5be3c8beeff209180cf471", 16), BigInt("4b009c5006cb3a34", 16), true)

  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  println(bigIntToHex(cipher))

  val plain  = TripleDES.decryptBlock(BigInt("54454f7e54454f7e54454f7e54454f7e54454f7e54454f7e", 16), cipher, true)

  println(bigIntToHex(plain))


}
