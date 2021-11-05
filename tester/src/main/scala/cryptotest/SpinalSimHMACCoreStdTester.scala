package cryptotest


import org.scalatest.funsuite.AnyFunSuite
import ref.mac.HMAC
import spinal.core._
import spinal.crypto.{BigIntToHexString, CastByteArray, Endianness}
import spinal.crypto.hash.md5.MD5Core_Std
import spinal.crypto.mac.hmac.{HMACCoreStdConfig, HMACCoreStdIO, HMACCore_Std}
import spinal.lib.slave
import spinal.sim._
import spinal.core.sim._

import scala.util.Random


class HMACCoreStd_MD5_Tester() extends Component {

  val md5  = new MD5Core_Std()
  val hmac = new HMACCore_Std(HMACCoreStdConfig(md5.configCore.hashBlockWidth, md5.configCore))

  val io = slave(HMACCoreStdIO(hmac.config))

  hmac.io.hmacCore <> io
  hmac.io.hashCore <> md5.io
}



class SpinalSimHMACCoreStdTester extends AnyFunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new HMACCoreStd_MD5_Tester())

  val NBR_ITERATION = 200

  /**
    * Test
    */
  test("HMACCoreStd_MD5"){

    compiledRTL.doSim{ dut =>

      val byteSizeMsg = dut.io.cmd.msg.getWidth / 8

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.init       #= false
      dut.io.cmd.valid  #= false

      dut.clockDomain.waitActiveEdge()

      var lenMsg = 1

      for(_ <- 0 to NBR_ITERATION){

        var msgStr = (List.fill(lenMsg)(Random.nextPrintableChar()).mkString(""))
        val keyStr = (List.fill(64)(Random.nextPrintableChar()).mkString(""))

        //        var msgStr = """RYWc/tA]1iG"""
        //        val keyStr = """0,m,U/s_^}<.|?<&DnTk#0q_R5-:,L*"""

        val msgStrOrginal = msgStr


        val refHmac = HMAC.digest(msgStr, keyStr, "HmacMD5")

        val keyByte = Endianness((keyStr.map(_.toByte).toList ::: List.fill(((dut.io.cmd.key.getWidth / 4) - keyStr.length * 2) / 2 )(0.toByte)).toArray)

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

          val msgByte = Endianness(msg.map(_.toByte).toArray)

          dut.io.cmd.valid #= true
          dut.io.cmd.msg   #= BigInt(0x00.toByte +: msgByte)
          dut.io.cmd.size  #= BigInt(if (isLast) msgStr.length - 1 else 0)
          dut.io.cmd.last  #= isLast
          dut.io.cmd.key   #= BigInt(0x00.toByte +: keyByte)


          // Wait the response
          if (isLast){
            waitUntil(dut.io.rsp.valid.toBoolean == true)

            val rtlHmac = CastByteArray(dut.io.rsp.hmac.toBigInt.toByteArray, dut.io.rsp.hmac.getWidth / 8)

            assert(
              refHmac == BigInt(Endianness(rtlHmac)),
              s"""
                 | REF != RTL    : ${BigIntToHexString(refHmac)} != ${BigIntToHexString(BigInt(0x00.toByte +: Endianness(rtlHmac)))}"
                 | Input message : ${msgStrOrginal}
                 | Key           : ${keyStr}
               """.stripMargin
            )

            dut.clockDomain.waitActiveEdge()
          }else {
            waitUntil(dut.io.cmd.ready.toBoolean == true)

            dut.clockDomain.waitActiveEdge()
          }

          // randomize the release of teh cmd.valid
          dut.io.cmd.valid #= false
          dut.clockDomain.waitActiveEdge()


          index -= 1
          msgStr = msgStr.drop(byteSizeMsg)
        }

        lenMsg += 1
      }
    }
  }
}