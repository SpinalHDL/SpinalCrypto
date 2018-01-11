package ref.symmetric

import java.security.MessageDigest
import java.security.spec.KeySpec
import java.util
import javax.crypto.spec.{PBEKeySpec, SecretKeySpec}
import javax.crypto.{SecretKey, SecretKeyFactory, Cipher}



object AES {


  /**
    * Encrypt/Decrypt a block
    */
  def block(keyLenght:Int, verbose: Boolean)(key: BigInt, block: BigInt, enc: Boolean) = if(enc) encryptBlock(key, block, keyLenght, verbose) else decryptBlock(key, block, keyLenght, verbose)


  /**
    * Block Encryption
    */
  def encryptBlock(key: BigInt, block: BigInt, keyLenght:Int, verbose: Boolean = false): BigInt = {

    // Cast the input key
    val keyModified = castByteArray(key.toByteArray, keyLenght / 8)
    val myKey       = new SecretKeySpec(keyModified, "AES")

    // Create the cipher
    val desCipher = Cipher.getInstance("AES/ECB/NoPadding")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.ENCRYPT_MODE, myKey)

    // cast input block
    val blockPlain = castByteArray(block.toByteArray, 16)

    // Encrypt the text
    val blockCipher = desCipher.doFinal(blockPlain)

    if(verbose){
      println(s"Plain  : 0x${blockPlain.map(b  => "%02X".format(b)).mkString("")}")
      println(s"KEY    : 0x${myKey.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Cipher : 0x${blockCipher.map(b => "%02X".format(b)).mkString("")}")
      println("")
    }

    return BigInt(blockCipher.take(16))
  }


  /**
    * Block Decryption
    */
  def decryptBlock(key: BigInt, block: BigInt, keyLenght:Int, verbose: Boolean = false): BigInt = {

    // cast input key
    val keyModified = castByteArray(key.toByteArray, keyLenght / 8)

    val myKey = new SecretKeySpec(keyModified, "AES")

    // Create the cipher
    val desCipher = Cipher.getInstance("AES/ECB/NoPadding")

    // Initialize the cipher for encryption
    desCipher.init(Cipher.DECRYPT_MODE, myKey)

    // cast input block
    val blockCipher = castByteArray(block.toByteArray, 16)

    // Encrypt the text

    val blockPlain = desCipher.doFinal(blockCipher)

    if(verbose){
      println(s"Cipher : 0x${blockCipher.map(b => "%02X".format(b)).mkString("")}")
      println(s"KEY    : 0x${myKey.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Plain  : 0x${blockPlain.map(b  => "%02X".format(b)).mkString("")}")
      println("")
    }

    return BigInt(blockPlain.take(16))
  }


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
}



// 128 => 16
// 192 => 24
// 256 => 32
object PlayWithRefAES extends App{

//  val cipher = AES.encryptBlock(BigInt("11223344", 16), BigInt("eca93cda1c63a01feca93cda1c63a01f", 16), 192,  true)
//
//  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"
//
//  println(bigIntToHex(cipher) + "\n")
//
//  val plain  = AES.decryptBlock(BigInt("000000e454454f7e000000e454454f7e54454f7e54454f7e", 16), cipher, 192,  true)
//
//  println(bigIntToHex(plain))
def getSecretKeySpec(
                      passphrase: String,
                      algorithm: String,
                      kgenbit: Int
                    ): SecretKeySpec = {
  val salt: Array[Byte] = Array(
    0xA9.asInstanceOf[Byte],
    0x87.asInstanceOf[Byte],
    0xC8.asInstanceOf[Byte],
    0x32.asInstanceOf[Byte],
    0x56.asInstanceOf[Byte],
    0xA5.asInstanceOf[Byte],
    0xE3.asInstanceOf[Byte],
    0xB2.asInstanceOf[Byte]
  )
  val iterationCount = 1024
  val keySpec: KeySpec = new PBEKeySpec(
    passphrase.toCharArray,
    salt,
    iterationCount
  )
  val secretKey: SecretKey = SecretKeyFactory.getInstance(
    "PBEWithMD5AndDES"
  ).generateSecret(keySpec)
  val md: MessageDigest = MessageDigest.getInstance("MD5")
  md.update(secretKey.getEncoded)
  md.update(salt)
  for (i <- 1 until iterationCount) {
    md.update(md.digest())
  }
  val keyBytes: Array[Byte] = md.digest
  val skeyspec: SecretKeySpec = new SecretKeySpec(keyBytes, algorithm)
  skeyspec
}


  def encrypt(
               message: Array[Byte],
               secret: String,
               scheme: String = "AES",
               bits: Int = 192
             ): Array[Byte] = {
    /*
    byte[] keyBytes = "ThisIs128bitSize".getBytes();
    Key key = new SecretKeySpec(keyBytes, "AES");
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.DECRYPT_MODE, key);
    byte[] decValue = c.doFinal(encryptedText);
    String decryptedValue = new String(decValue);
    return decryptedValue;
    */
    val skeySpec: SecretKeySpec = getSecretKeySpec(secret, scheme, bits)
    //val skeySpec: SecretKeySpec = new SecretKeySpec(secret.toByte, "AES")
    println(skeySpec)
    val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
    println(skeySpec.getAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec)
    val encrypted: Array[Byte] = cipher.doFinal(message)
    encrypted
  }

  /**
    * Decrypt a byte array given the same secret key spec used to encrypt the
    * message.

    */
  def decrypt(
               message: Array[Byte],
               secret: String,
               scheme: String = "AES",
               bits: Int = 192
             ): Array[Byte] = {
    val skeySpec: SecretKeySpec = getSecretKeySpec(secret, scheme, bits)
    val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")

    cipher.init(Cipher.DECRYPT_MODE, skeySpec)
    val decrypted: Array[Byte] = cipher.doFinal(message)
    decrypted
  }

  def asHexStr(buf: Array[Byte]): String = {
    import java.lang.{Long => JLong}
    val strbuf: StringBuffer = new StringBuffer(buf.length * 2)
    for (i <- 0 until buf.length) {
      if ((buf(i).asInstanceOf[Int] & 0xff) < 0x10) {
        strbuf.append("0")
      }
      strbuf.append(JLong.toString(buf(i).asInstanceOf[Int] & 0xff, 16))
    }
    strbuf.toString
  }



  var message: String = "This is just an "
  System.out.println("(HEX) Original  : " + asHexStr(message.getBytes))
  var encrypted: Array[Byte] = encrypt(message.getBytes, "1111111122222222333333334444444411111111222222223333333344444444", "AES", 256)
  System.out.println("(HEX) Encrypted : " + asHexStr(encrypted))
  var decrypted: Array[Byte] = decrypt(encrypted, "mypassword", "AES", 128)
  System.out.println("(HEX) Decrypted : " + asHexStr(decrypted))
  if (util.Arrays.equals(decrypted, message.getBytes)) {
    System.out.println("THE ONE AND THE SAME")
  }




}