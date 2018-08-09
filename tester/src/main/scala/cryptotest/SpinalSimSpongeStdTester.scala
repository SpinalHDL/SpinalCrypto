package cryptotest

import spinal.core._
import spinal.sim._
import spinal.core.sim._
import org.scalatest.FunSuite
import spinal.crypto.BigIntToHexString
import spinal.crypto.construtor.{SpongeIO_Std, Sponge_Std}
import spinal.crypto.primitive.keccak.KeccakF_Std
import spinal.lib._



class SpinalSimSpongeStdTester extends FunSuite {

  class KeccakSponge() extends Component {

    val io =  slave(SpongeIO_Std(576, 512))

    val sponge = new Sponge_Std(1024, 576, 512)
    val func   = new KeccakF_Std(1600)

    sponge.io.func <> func.io
    sponge.io.sponge <> io
  }


  test("Sponge_Keccak_1600_512"){

    SimConfig.withWave(4).withConfig(SpinalConfig(inlineRom = true)).compile(new KeccakSponge()).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // pattern
      val pIn = List(
        List(
          BigInt("000000000000064100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000", 16)    // A
        ),
        List(
          BigInt("00000000000000d300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000", 16)    // 5-bit
        ),
        List(
          BigInt("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", 16),   // 1063-bit
          BigInt("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", 16),
          BigInt("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A300000001A3A3A3A38000000000000000", 16)
        )
      )

      val pOut = List(
        BigInt("f5f0eaa9ca3fd0c4e0d72a3471e4b71edaabe2d01c4b25e16715004ed91e663a1750707cc9f04430f19b995f4aba21b0ec878fc5c4eb838a18df5bf9fdc949df", 16),
        BigInt("A13E01494114C09800622A70288C432121CE70039D753CADD2E006E4D961CB27544C1481E5814BDCEB53BE6733D5E099795E5E81918ADDB058E22A9F24883F37", 16),
        BigInt("CF9A30AC1F1F6AC0916F9FEF1919C595DEBE2EE80C85421210FDF05F1C6AF73AA9CAC881D0F91DB6D034A2BBADC1CF7FBCB2ECFA9D191D3A5016FB3FAD8709C9", 16)
      )


      var index = 0

      // send differnt pattern
      while(index != pIn.length){

        var indexBlock = 0

        // initialize value
        dut.io.init       #= true
        dut.io.cmd.last   #= false
        dut.io.cmd.valid  #= false
        dut.io.cmd.n.randomize()

        dut.clockDomain.waitActiveEdge()

        dut.io.init #= false

        // Send all block in the sponge
        while(indexBlock != pIn(index).length){

          dut.clockDomain.waitActiveEdge()

          dut.io.cmd.last  #= (indexBlock == pIn(index).length - 1)
          dut.io.cmd.valid #= true
          dut.io.cmd.n     #= pIn(index)(indexBlock)

          dut.clockDomain.waitActiveEdgeWhere(dut.io.cmd.ready.toBoolean)
          dut.io.cmd.valid #= false

          val rtlState_out = BigInt(dut.io.rsp.z.toBigInt.toByteArray.takeRight(dut.io.rsp.z.getWidth / 8))
          println(s"${BigIntToHexString(rtlState_out)}")
          //val rtlState_out = BigInt(dut.io.rsp.string.toBigInt.toByteArray.takeRight(dut.io.rsp.string.getWidth / 8))
          //val refState_out = BigInt(pOut(index).toByteArray.takeRight(dut.io.rsp.string.getWidth / 8))

          //assert(rtlState_out == refState_out , s"Wrong result RTL ${BigIntToHexString(rtlState_out)} !=  REF ${BigIntToHexString(refState_out)}")

          indexBlock += 1
        }

        dut.clockDomain.waitActiveEdge(5)

        index += 1
      }
    }
  }
}

