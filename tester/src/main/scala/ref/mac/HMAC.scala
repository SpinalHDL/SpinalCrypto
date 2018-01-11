package ref.mac


import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


object HMAC {

  def digest(msg: String, keyString: String, algo: String): String = {
    var digest: String = null

    try {
      val key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo)
      val mac = Mac.getInstance(algo)
      mac.init(key)
      val bytes = mac.doFinal(msg.getBytes("ASCII"))
      val hash  = new StringBuffer()


      for(i <- 0 until bytes.length){
        val hex = Integer.toHexString(0xFF & bytes(i))
        if (hex.length() == 1) {
          hash.append('0')
        }
        hash.append(hex)
      }
      digest = hash.toString()
    } catch {
      case e: Throwable => ()
    }

    return digest
  }
}

object PlayWithHMacRef extends App{
  println(HMAC.digest("The quick brown fox jumps over the lazy dog", "key", "HmacMD5"))


}