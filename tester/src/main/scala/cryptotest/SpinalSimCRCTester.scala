package cryptotest

/**
  * Created by snoopy on 09.02.18.
  */
class SpinalSimCRCTester {

}



object PlayWithCRC extends App {
  import java.util.zip.CRC32
  val crc=new CRC32
  crc.update("The quick brown fox jumps over the lazy dog".getBytes)
  println(crc.getValue.toHexString)  //> 414fa339
}