package cryptotest

import spinal.core._
import spinal.core.sim._
import org.scalatest.funsuite.AnyFunSuite
import ref.padding.Pad_xB_1_Ref
import spinal.crypto.{BigIntToHexString, CastByteArray}
import spinal.crypto.padding.{Pad_xB_1_Std, Padding_xB_1_Config}


import scala.util.Random



class SpinalSimPad_xB_1_StdTester extends AnyFunSuite {


  /**
    * Pad_06_1_576_32
    */
  test("Pad_06_1_576_32"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new Pad_xB_1_Std(Padding_xB_1_Config(32 bits, 576 bits, 0x06, 8 bits))).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      var iteration = 100

      while(iteration != 0){

        // pattern
        val pIn  = List.fill(iteration)(Random.nextPrintableChar()).mkString("")

        val byteSizeMsg = 4

        // initialize value
        dut.io.init       #= true
        dut.io.cmd.last   #= false
        dut.io.cmd.valid  #= false
        dut.io.cmd.data.randomize()

        dut.io.rsp.ready #= true

        dut.clockDomain.waitActiveEdge()

        dut.io.init #= false

        var indexPin = scala.math.ceil(pIn.length  / byteSizeMsg.toDouble).toInt

        var msgStr = pIn
        val refOut = Pad_xB_1_Ref(pIn, 32, 576)

        /**
          * Manage the response and check the result
          */
        fork{

          var index = 0

          while(index != refOut.length) {

            dut.clockDomain.waitActiveEdgeWhere(dut.io.rsp.valid.toBoolean)

            val rtlOut = CastByteArray(dut.io.rsp.data.toBigInt.toByteArray, dut.io.rsp.data.getWidth / 8)

            assert(BigIntToHexString(BigInt(rtlOut)) == s"0x${refOut(index)}", s"REF != RTL ${refOut(index)} != ${BigIntToHexString(BigInt(rtlOut))}")

            dut.clockDomain.waitActiveEdge()

            index += 1
          }
        }

        /**
          * Send all block in the sponge
          */
        while(indexPin != 0){

          val (msg, isLast) = if (msgStr.length > byteSizeMsg) (msgStr.substring(0, byteSizeMsg) -> false) else (msgStr + 0.toChar.toString * (byteSizeMsg - msgStr.length) -> true)

          dut.clockDomain.waitActiveEdge()

          dut.io.cmd.last  #= isLast
          dut.io.cmd.valid #= true
          dut.io.cmd.data  #= BigInt(0x00.toByte +: (msg.map(_.toByte).toArray)  )// Add 00 in front in order to get a positif number
          dut.io.cmd.size  #= BigInt(if (isLast) msgStr.length - 1 else 0)

          // Wait the response
          dut.clockDomain.waitActiveEdgeWhere(dut.io.cmd.ready.toBoolean)

          dut.io.cmd.valid #= false

          indexPin -= 1
          msgStr = msgStr.drop(byteSizeMsg)
        }

        dut.clockDomain.waitActiveEdge(5)

        iteration -= 1
      }
    }
  }
}


