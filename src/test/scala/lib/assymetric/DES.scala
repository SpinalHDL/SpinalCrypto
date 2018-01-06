package lib.assymetric

import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Cipher, KeyGenerator}



/**
  * Created by snoopy on 03.01.18.
  */
object DES {

  /**
    * Encrypt/Decrypt a block
    */
  def block(verbose: Boolean)(key: BigInt, block: BigInt, enc: Boolean) = if(enc) encryptBlock(key, block, verbose) else decryptBlock(key, block, verbose)


  /**
    * Block Encryption
    */
  def encryptBlock(key: BigInt, block: BigInt, verbose: Boolean = false ): BigInt = {

    // Cast the input key
    val keyModified = castByteArray(key.toByteArray)
    val myDesKey = new SecretKeySpec(keyModified, "DES")

    // Create the cipher
    val desCipher = Cipher.getInstance("DES/ECB/NoPadding")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.ENCRYPT_MODE, myDesKey)

    // cast input block
    val blockPlain = castByteArray(block.toByteArray)

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
    val keyModified = castByteArray(key.toByteArray)

    val myDesKey = new SecretKeySpec(keyModified, "DES")

    // Create the cipher
    val desCipher = Cipher.getInstance("DES/ECB/NoPadding")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.DECRYPT_MODE, myDesKey)

    // cast input block
    val blockCipher = castByteArray(block.toByteArray)

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
    * Cast the input array to 8 byte
    */
  private def castByteArray(input: Array[Byte]): Array[Byte] = input.length match{
    case 8              => input
    case s:Int if s > 8 => input.takeRight(8)
    case s:Int if s < 8 => Array.fill[Byte](8 - input.length)(0x00) ++ input
  }
}




object PlayWithRefDES extends App{

  val cipher = DES.encryptBlock(BigInt("e454454f7e", 16), BigInt("eca93cda1c63a01f", 16), true)

  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  println(bigIntToHex(cipher))

  val plain  = DES.decryptBlock(BigInt("000000e454454f7e", 16), cipher, true)

  println(bigIntToHex(plain))


}
