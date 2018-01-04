package lib.assymetric

import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Cipher, KeyGenerator, SecretKey}



/**
  * Created by snoopy on 03.01.18.
  */
object DES {

  def encryptBlock(key: BigInt, block: BigInt, verbose: Boolean = false ): BigInt = {


    val keygenerator = KeyGenerator.getInstance("DES")

    val keyByte  = key.toByteArray
    val keyModified = keyByte.length match{
      case 8              => keyByte
      case s:Int if s > 8 => keyByte.takeRight(8)
      case s:Int if s < 8 => Array.fill[Byte](8 - keyByte.length)(0x00) ++ keyByte
    }

    val myDesKey = new SecretKeySpec(keyModified, "DES")


    // Create the cipher
    val desCipher = Cipher.getInstance("DES")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.ENCRYPT_MODE, myDesKey)

    //sensitive information
    //val text = "No body can see me".getBytes()
    val blockByte = block.toByteArray.takeRight(8)
    val text = blockByte.length match{
      case 8              => blockByte
      case s:Int if s > 8 => blockByte.takeRight(8)
      case s:Int if s < 8 => Array.fill[Byte](8 - blockByte.length)(0x00) ++ blockByte
    }

    // Encrypt the text
    val textEncrypted = desCipher.doFinal(text)

    if(verbose){
      println(s"Block : 0x${text.map(b => "%02X".format(b)).mkString("")}")
      println(s"KEY : 0x${myDesKey.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Cipher : 0x${textEncrypted.map(b => "%02X".format(b)).mkString("")}")
      println("")
    }

    return BigInt(textEncrypted.take(8))
  }
}

object PlayWithDES extends App{

  DES.encryptBlock(BigInt("e454454f7e", 16), BigInt("eca93cda1c63a01f", 16))

  val key: Array[Byte] = Array(0x0e, 0x45, 0x44, 0x54, 0xf7, 0xf7, 0x97, 0x7e).map(_.toByte)

  val keygenerator = KeyGenerator.getInstance("DES")
  //val myDesKey     = keygenerator.generateKey()
  val myDesKey = new SecretKeySpec(key, "DES")






  val encoded = myDesKey.getEncoded()
  encoded.foreach(b => println("%02X".format(b)))
  /* Now store "encoded" somewhere. For example, display the key and
     ask the user to write it down. */
  val output = Base64.getEncoder().withoutPadding().encodeToString(encoded)
  println(output)

  // Create the cipher
  val desCipher = Cipher.getInstance("DES")

  // Initialize the cipher for encryption
  desCipher.init(Cipher.ENCRYPT_MODE, myDesKey)

  //sensitive information
  //val text = "No body can see me".getBytes()
  val text: Array[Byte] = Array(0xec, 0xa9, 0x3c, 0xda, 0x1c, 0x63, 0xa0, 0x1f).map(_.toByte)
  text.foreach(b => println("%02X".format(b)))


  println("Text [Byte Format] : " + text)
  println("Text : " + new String(text))

  // Encrypt the text
  val textEncrypted = desCipher.doFinal(text)

  println("Text Encryted : " + textEncrypted)
  textEncrypted.foreach(b => println("%02X".format(b)))

  // Initialize the same cipher for decryption
  desCipher.init(Cipher.DECRYPT_MODE, myDesKey);

  // Decrypt the text
  val textDecrypted = desCipher.doFinal(textEncrypted);

  System.out.println("Text Decryted : " + new String(textDecrypted));
}
