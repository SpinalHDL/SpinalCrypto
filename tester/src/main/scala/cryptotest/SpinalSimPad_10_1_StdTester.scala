package cryptotest



import spinal.core._
import spinal.sim._
import spinal.core.sim._
import org.scalatest.FunSuite
import spinal.crypto.{BigIntToHexString, CastByteArray}
import spinal.crypto.padding.{Pad_10_1_Std, PaddingConfig}
import spinal.lib._



class SpinalSimPad_10_1_StdTester extends FunSuite {


  test("Pad_10_1_572_32"){

    SimConfig.withWave(4).withConfig(SpinalConfig(inlineRom = true)).compile(new Pad_10_1_Std(PaddingConfig(32 bits, 572 bits, 8 bits))).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // pattern
      val pIn = List(
          "a3",
          "a3a3",
          "LLA3A3A3A3"
      )

      val pOut = List(
        BigInt("f5f0eaa9ca3fd0c4e0d72a3471e4b71edaabe2d01c4b25e16715004ed91e663a1750707cc9f04430f19b995f4aba21b0ec878fc5c4eb838a18df5bf9fdc949df", 16),
        BigInt("A13E01494114C09800622A70288C432121CE70039D753CADD2E006E4D961CB27544C1481E5814BDCEB53BE6733D5E099795E5E81918ADDB058E22A9F24883F37", 16),
        BigInt("CF9A30AC1F1F6AC0916F9FEF1919C595DEBE2EE80C85421210FDF05F1C6AF73AA9CAC881D0F91DB6D034A2BBADC1CF7FBCB2ECFA9D191D3A5016FB3FAD8709C9", 16)
      )

      val byteSizeMsg = 4
      var index = 0


      // send differnt pattern
      while(index != pIn.length){

        // initialize value
        dut.io.init       #= true
        dut.io.cmd.last   #= false
        dut.io.cmd.valid  #= false
        dut.io.cmd.data.randomize()

        dut.io.rsp.ready #= true

        dut.clockDomain.waitActiveEdge()

        dut.io.init #= false

        var indexPin = scala.math.ceil(pIn(index).length  / byteSizeMsg.toDouble).toInt

        var msgStr = pIn(index)

        // Send all block in the sponge
        while(indexPin != 0){

          println(msgStr)

          val (msg, isLast) = if (msgStr.length > byteSizeMsg) (msgStr.substring(0, byteSizeMsg) -> false) else (msgStr + 0.toChar.toString * (byteSizeMsg - msgStr.length) -> true)

          dut.clockDomain.waitActiveEdge()

          dut.io.cmd.last  #= isLast
          dut.io.cmd.valid #= true
          dut.io.cmd.data  #= BigInt(0x00.toByte +: (msg.map(_.toByte).toArray)  )// Add 00 in front in order to get a positif number
          dut.io.cmd.size  #= BigInt(if (isLast) msgStr.length - 1 else 0)

          dut.clockDomain.waitActiveEdge()

          // Wait the response
          dut.clockDomain.waitActiveEdgeWhere(dut.io.cmd.ready.toBoolean)
          /*if (isLast){
            waitUntil(dut.io.rsp.valid.toBoolean == true)

            //val rtlDigest = CastByteArray(dut.rsp.digest.toBigInt.toByteArray, dut.cmd.msg.getWidth)

            //if(endianess == LITTLE_endian){
            //  assert(CastByteArray(refDigest, dut.cmd.msg.getWidth).sameElements(Endianness(rtlDigest)), s"REF != RTL ${BigIntToHexString(BigInt(refDigest))} != ${BigIntToHexString(BigInt(Endianness(rtlDigest)))}")
            //}else{
            //  assert(CastByteArray(refDigest, dut.cmd.msg.getWidth).sameElements(rtlDigest), s"REF != RTL ${BigIntToHexString(BigInt(refDigest))} != ${BigIntToHexString(BigInt(rtlDigest))}")



            dut.clockDomain.waitActiveEdge()
          }else {
            waitUntil(dut.io.cmd.ready.toBoolean == true)
          }
          */

          indexPin -= 1
          msgStr = msgStr.drop(byteSizeMsg)
        }

        dut.io.cmd.valid #= false

        dut.clockDomain.waitActiveEdge(5)

        index += 1
      }
    }
  }
}


