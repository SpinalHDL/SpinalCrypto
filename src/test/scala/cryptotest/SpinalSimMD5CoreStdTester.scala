package cryptotest


import org.scalatest.FunSuite
import ref.hash.MD5
import ref.symmetric.DES
import spinal.crypto.hash.md5.MD5Core_Std

import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim

import spinal.sim._
import spinal.core.sim._


import scala.util.Random



class SpinalSimMD5CoreStdTester extends FunSuite {


  def bigIntToHex(value: BigInt): String = s"0x${value.toByteArray.map(b => f"${b}%02X").mkString("")}"

  // RTL to simulate
  val compiledRTL = SimConfig.withWave(2).compile(new MD5Core_Std())


  def endianess(input: Array[Byte]): Array[Byte] = {
    assert(input.length % 4 == 0)

    return input.grouped(4).flatMap(_.reverse.toList).toArray
  }

  def castByteArray(input: Array[Byte], castSize: Int): Array[Byte] = {
    if(input.length == castSize){
      input
    }else if(input.length > castSize){
      input.takeRight(castSize)
    }else{
      Array.fill[Byte](castSize - input.length)(0x00) ++ input
    }
  }


  /**
    * Test 1
    */
  test("MD5CoreStd_notReleaseValid") {

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.init      #= false
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()


      dut.io.init      #= true

      dut.clockDomain.waitActiveEdge()

      dut.io.init      #= false

      dut.clockDomain.waitActiveEdge()

      var msgHex = "righsumvrxtvypeeprqcbzksv" // 132b9e56f59562c1f36dc4f04752d8e7 Random.nextString(5)
      val refDigest = MD5.digest(msgHex)

      var index = math.ceil(msgHex.length  / 4.0).toInt

      println(index, " ", msgHex.length)

      while(index != 0) {
        val (msg, isLast) = if (msgHex.length > 4) (msgHex.substring(0, 4) -> false) else (msgHex + 0.toChar.toString * (4 - msgHex.length) -> true)

        dut.io.cmd.valid #= true
        dut.io.cmd.msg   #= BigInt(msg.map(_.toByte).reverse.toArray)
        dut.io.cmd.size  #= BigInt(if (isLast) msgHex.length - 1 else 0)
        dut.io.cmd.last  #= isLast

        dut.clockDomain.waitActiveEdge()

        if (isLast){

          waitUntil(dut.io.rsp.valid.toBoolean == true)

          val rtlDigest = castByteArray(dut.io.rsp.digest.toBigInt.toByteArray, 32)

          println(bigIntToHex(BigInt(endianess(rtlDigest))))
          println(bigIntToHex(BigInt(refDigest)))



          dut.clockDomain.waitActiveEdge()
        }else {
          waitUntil(dut.io.cmd.ready.toBoolean == true)
        }

        dut.io.cmd.valid #= false

        dut.clockDomain.waitActiveEdge()

        index -= 1
        msgHex = msgHex.drop(4)
      }
    }
  }
}