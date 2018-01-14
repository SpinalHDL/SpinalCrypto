package cryptotest


import org.scalatest.FunSuite
import ref.mac.HMAC
import ref.symmetric.DES
import spinal.core._
import spinal.crypto.{BigIntToHexString, Endianness, CastByteArray}
import spinal.crypto.hash.md5.MD5Core_Std
import spinal.crypto.mac.hmac.{HMACCoreStdIO, HMACCoreStdGeneric, HMACCore_Std}

import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.lib.slave

import spinal.sim._
import spinal.core.sim._

import scala.util.Random


class HMACCoreStd_MD5_Tester() extends Component{

  val md5  = new MD5Core_Std()
  val hmac = new HMACCore_Std(HMACCoreStdGeneric(md5.g.hashBlockWidth, md5.g))

  val io = slave(HMACCoreStdIO(hmac.g))

  hmac.io.hmacCore <> io
  hmac.io.hashCore <> md5.io
}



class SpinalSimHMACCoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withWave(2).compile(new HMACCoreStd_MD5_Tester())


  /**
    * Test 1
    */
  test("HMACCoreStd_MD5"){

    compiledRTL.doSim{ dut =>

      val byteSizeMsg = dut.io.cmd.msg.getWidth / 8

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.init       #= false
      dut.io.cmd.valid  #= false

      dut.clockDomain.waitActiveEdge()


      Suspendable.repeat(1){

        //var msgStr = List.fill(10)(Random.nextPrintableChar()).mkString("")
        //val keyStr = List.fill(10)(Random.nextPrintableChar()).mkString("")
        var msgStr = "wwekmebfdwkarbxwbjjfbjwunfbovhguihldbmyfpwxqhtgbszzyjuewylwpnuzswhunxogzgvnxjvatoimzyieyhqgktsfvszz"
        val keyStr = "ghbkapojbkibfotjloeyqwzjtxvipc"

        val refHmac = HMAC.digest(msgStr, keyStr, "HmacMD5")

        println(msgStr, keyStr, refHmac)

        // init HMAC
        dut.clockDomain.waitActiveEdge()
        dut.io.init      #= true
        dut.clockDomain.waitActiveEdge()
        dut.io.init      #= false
        dut.clockDomain.waitActiveEdge()

        // number of iteration
        var index = math.ceil(msgStr.length  / byteSizeMsg.toDouble).toInt

        // Send all block of message
        while(index != 0) {

          val (msg, isLast) = if (msgStr.length > byteSizeMsg) (msgStr.substring(0, byteSizeMsg) -> false) else (msgStr + 0.toChar.toString * (byteSizeMsg - msgStr.length) -> true)

          dut.io.cmd.valid #= true
          dut.io.cmd.msg   #= BigInt(0x00.toByte +: (msg.map(_.toByte).reverse.toArray)) // Add 00 in front in order to get a positif number
          dut.io.cmd.size  #= BigInt(if (isLast) msgStr.length - 1 else 0)
          dut.io.cmd.last  #= isLast
          dut.io.cmd.key   #= BigInt(0x00.toByte +: (keyStr.map(_.toByte).reverse.toArray))

          dut.clockDomain.waitActiveEdge()

          // Wait the response
          if (isLast){
            waitUntil(dut.io.rsp.valid.toBoolean == true)

            val rtlHmac = CastByteArray(dut.io.rsp.hmac.toBigInt.toByteArray, dut.io.cmd.msg.getWidth)

            println(refHmac, BigIntToHexString(BigInt(rtlHmac)))
            //assert(CastByteArray(refHmac, dut.io.cmd.msg.getWidth).sameElements(Endianness(rtlHmac)), s"REF != RTL ${BigIntToHexString(BigInt(refHmac))} != ${BigIntToHexString(BigInt(Endianness(rtlHmac)))}")

            dut.clockDomain.waitActiveEdge()
          }else {
            waitUntil(dut.io.cmd.ready.toBoolean == true)
          }

          dut.io.cmd.valid #= false

          dut.clockDomain.waitActiveEdge()

          index -= 1
          msgStr = msgStr.drop(byteSizeMsg)
        }


      }

    }
  }

}