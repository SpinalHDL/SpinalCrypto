package ref.symmetric

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


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
    val keyAlgo = new SecretKeySpec(castByteArray(key.toByteArray, keySize), algoName)

    // Create the cipher
    val algorithm = Cipher.getInstance(s"$algoName/$chainning/$padding")

    // Initialize the cipher for encryption
    algorithm.init(if(enc) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, keyAlgo)

    // cast input block
    val block_in = castByteArray(block.toByteArray, blockSize)

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


object PlayWithSymmetricRef{

}
