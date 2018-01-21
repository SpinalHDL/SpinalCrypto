package ref.symmetric

import java.security.SecureRandom
import javax.crypto.{Cipher, KeyGenerator}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

import spinal.crypto.{BigIntToHexString, CastByteArray}

import scala.util.Random





/**
  * DES
  */
object DES {

  def block(verbose: Boolean)(key: BigInt, block: BigInt, enc: Boolean) = {
    if(enc) {
      Symmetric.block(
        key       = key,
        block     = block,
        blockSize = 8,
        keySize   = 8,
        algoName  = "DES",
        chainning = "ECB",
        padding   = "NoPadding",
        enc       = true,
        verbose   = verbose)
    } else {
      Symmetric.block(
        key       = key,
        block     = block,
        blockSize = 8,
        keySize   = 8,
        algoName  = "DES",
        chainning = "ECB",
        padding   = "NoPadding",
        enc       = false,
        verbose   = verbose)
    }
  }

  def blockRaw(verbose: Boolean)(key: Array[Byte], block: Array[Byte], iv: Array[Byte], enc: Boolean, algoName: String, chainning: String, padding: String): Array[Byte] = {

    // Cast the input key
    val keyAlgo = new SecretKeySpec(key, algoName)

    // iv
    val dpIV = new IvParameterSpec(iv)

    // Create the cipher
    val algorithm = Cipher.getInstance(s"$algoName/$chainning/$padding")

    // Initialize the cipher for encryption
    algorithm.init(if(enc) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, keyAlgo, dpIV)

    // cast input block
    val block_in = block

    // Encrypt the text
    val block_out = algorithm.doFinal(block_in)

    if(verbose){
      println(s"Block_in  : 0x${block_in.map(b => "%02X".format(b)).mkString("")}")
      println(s"Key       : 0x${keyAlgo.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Block_out : 0x${block_out.map(b => "%02X".format(b)).mkString("")}")
      println("")
    }

    return block_out
  }
}


/**
  * Triple DES
  */
object TripleDES {

  def block(verbose: Boolean)(key: BigInt, block: BigInt, enc: Boolean) = {
    if(enc) {
      Symmetric.block(
        key       = key,
        block     = block,
        blockSize = 8,
        keySize   = 3 * 8,
        algoName  = "DESede",
        chainning = "ECB",
        padding   = "NoPadding",
        enc       = true,
        verbose   = verbose)
    } else {
      Symmetric.block(
        key       = key,
        block     = block,
        blockSize = 8,
        keySize   = 3 * 8,
        algoName  = "DESede",
        chainning = "ECB",
        padding   = "NoPadding",
        enc       = false,
        verbose   = verbose)
    }
  }
}




object Symmetric {


  /**
    * Block Encryption
    */
  def block(key: BigInt, block: BigInt, blockSize:Int, keySize:Int, algoName: String, chainning: String, padding: String, enc: Boolean, verbose: Boolean = false ): BigInt = {

    // Cast the input key
    val keyAlgo = new SecretKeySpec(CastByteArray(key.toByteArray, keySize), algoName)


    // Create the cipher
    val algorithm = Cipher.getInstance(s"$algoName/$chainning/$padding")

    // Initialize the cipher for encryption
    algorithm.init(if(enc) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, keyAlgo)

    // cast input block
    val block_in = CastByteArray(block.toByteArray, blockSize)


    // Encrypt the text
    val block_out = algorithm.doFinal(block_in)

    if(verbose){
      println(s"Block_in  : 0x${block_in.map(b => "%02X".format(b)).mkString("")}")
      println(s"Key       : 0x${keyAlgo.getEncoded().map(b => "%02X".format(b)).mkString("")}")
      println(s"Block_out : 0x${block_out.map(b => "%02X".format(b)).mkString("")}")
      println("")
    }

    return BigInt(block_out.take(blockSize))
  }

}


object PlayWithSymmetricRef extends App {

  val c   = Cipher.getInstance("DES/CTR/NoPadding")

  val key = new SecretKeySpec(CastByteArray(BigInt(0x111).toByteArray, 8), "DES")

  val iv = CastByteArray(BigInt(0x111).toByteArray, 8)
  val dps = new IvParameterSpec(iv)

  c.init(Cipher.ENCRYPT_MODE, key, dps)
  val input = "Stand and unfold".getBytes()
  val encrypted = c.doFinal(input)
  println(BigIntToHexString(BigInt(encrypted)))


  c.init(Cipher.DECRYPT_MODE, key, dps)
  val output = c.doFinal(encrypted)
  println(BigIntToHexString(BigInt(output)))

////
////  val key_          = BigInt(64, Random)
////  val blockIn_      = BigInt(64 * 3, Random)
////  val enc_          = Random.nextBoolean()
////  val ref_blockOut_ = DES.blockWithChaining(true)(key_, blockIn_, (64 * 3) / 8,  enc_, "CBC")


}
