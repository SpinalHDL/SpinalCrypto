package ref.mac


import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import spinal.crypto.BigIntToHexString


object HMAC {

  def digest(msg: String, keyString: String, algo: String): BigInt = {

      val key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo)
      val mac = Mac.getInstance(algo)
      mac.init(key)
      val bytes = mac.doFinal(msg.getBytes("ASCII"))

      return BigInt(bytes)
  }
}

object PlayWithHMacRef extends App{

//  ('key  : ', 'ghbkapojbkibfotjloeyqwzjtxvipc')
//  ('key  : ', '6768626b61706f6a626b6962666f746a6c6f657971777a6a747876697063')
//  ('msg  : ', 'wwekmebfdwkarbxwbjjfbjwunfbovhguihldbmyfpwxqhtgbszzyjuewylwpnuzswhunxogzgvnxjvatoimzyieyhqgktsfvszz')
//  ('msg  : ', '7777656b6d65626664776b6172627877626a6a66626a77756e66626f7668677569686c64626d79667077787168746762737a7a796a756577796c77706e757a737768756e786f677a67766e786a7661746f696d7a796965796871676b74736676737a7a')
//  ('hmac : ', '5812b025c7b64aacc7fd97b68d518430')


//  println(HMAC.digest("The quick brown fox jumps over the lazy dog", "key", "HmacMD5"))

  println(HMAC.digest("wwekmebfdwkarbxwbjjfbjwunfbovhguihldbmyfpwxqhtgbszzyjuewylwpnuzswhunxogzgvnxjvatoimzyieyhqgktsfvszz", "ghbkapojbkibfotjloeyqwzjtxvipc", "HmacMD5"))


}