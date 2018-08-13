package cryptotest

import spinal.core._
import spinal.sim._
import spinal.core.sim._
import org.scalatest.FunSuite
import spinal.crypto.{BigIntToHexString, CastByteArray}
import spinal.crypto.construtor.{SpongeCoreCmd_Std, SpongeCoreRsp_Std, SpongeCore_Std}
import spinal.crypto.primitive.keccak.{FuncIO_Std, KeccakF_Std}
import spinal.lib._


object PlayWithSpongefunc extends App{

  def sponge(msg: Array[Byte], c: Int, r: Int, d: Int): Array[Byte] ={

    val msgCut = msg.sliding(r, r)
    val rReg = Array.fill(r)(0x00.toByte)

    // Absorbing...
    for(m <- msgCut){

      println("msg", m.map(x => f"$x%02X").mkString(","))

      // XOR
      val xored = rReg.zip(m).map{case(a,b) => (a ^ b).toByte}
      println("xor", xored.map(x => f"$x%02X").mkString(","))

      // SHIFT
      val shift = xored.slice(1, xored.length) :+ 0x00.toByte
      println("shift", shift.map(x => f"$x%02X").mkString(","))

      for(i <- 0 until rReg.length) rReg(i) = shift(i)
    }


    return rReg

  }

  sponge(Array(0x10, 0x20, 0x40, 0x50, 0x60, 0xff, 0xee, 0xdd, 0xaa, 0x00).map(_.toByte), 4, 5, 10)
}


class SpinalSimSpongeStdTester extends FunSuite {


  def sponge(msg: Array[Byte], c: Int, r: Int, d: Int): Array[Byte] ={

    val msgCut = msg.sliding(r / 8, r / 8)
    val rReg = Array.fill(r / 8)(0x00.toByte)
    val cReg = Array.fill(c / 8)(0x00.toByte)

    // Absorbing...
    for(m <- msgCut){

      println("msg", msg.length,  m.map(x => f"$x%02X").mkString(","))

      // XOR
      val xored = rReg.zip(m).map{case(a,b) => (a ^ b).toByte}
      println("xor", xored.length, xored.map(x => f"$x%02X").mkString(","))

      // SHIFT
      val shift = (xored ++ cReg).slice(1, xored.length + cReg.length) :+ 0x00.toByte
      println("shift", shift.length, shift.map(x => f"$x%02X").mkString(","))

      println(rReg.length, cReg.length, shift.length)

      for(i <- 0 until rReg.length) rReg(i) = shift(i)
      for(i <- 0 until cReg.length) cReg(i) = shift(i + rReg.length - 1)
    }

    // Squeezing ..
    // ...

    return rReg.slice(0, d / 8)

  }


  class FakeSponge() extends Component {

    val io =  new Bundle{
      val init   = in Bool
      val cmd    = slave(Stream(Fragment(SpongeCoreCmd_Std(576))))
      val rsp    = master(Flow(SpongeCoreRsp_Std(512)))
    }

    val sponge = new SpongeCore_Std(1024, 576, 512)
    val rTmp = Reg(cloneOf(sponge.io.func.cmd.payload))
    val start = RegInit(False)

    sponge.io.func.cmd.ready := False
    sponge.io.func.rsp.payload := rTmp
    sponge.io.func.rsp.valid   := False


    val timeout = Timeout(3 cycles)

    when(sponge.io.func.cmd.valid & !start){
      start := True
      rTmp := B(sponge.io.func.cmd.payload |<< 8)
      timeout.clear()
    }

    when(timeout & start){
      sponge.io.func.cmd.ready := True
      sponge.io.func.rsp.valid := True
      timeout.clear()
      start := False
    }

    sponge.io.cmd  <> io.cmd
    sponge.io.rsp  <> io.rsp
    sponge.io.init <> io.init
  }




  test("Sponge_1600_noSqueezing"){

    SimConfig.withWave(4).withConfig(SpinalConfig(inlineRom = true)).compile(new FakeSponge()).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // pattern
      val pIn = List(
        List(
          BigInt("000000000000064100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000", 16)    // A
        ),
        List(
          BigInt("A13E01494114C09800622A70288C432121CE70039D753CADD2E006E4D961CB27544C1481E5814BDCEB53BE6733D5E099795E5E81918ADDB058E22A9F24883F337cc9f04430123AE3", 16),   // 1063-bit
          BigInt("f5f0eaa9ca3fd0c4e0d72a3471e4b71edaabe2d01c4b25e16715004ed91e663a1750707cc9f04430f19b995f4aba21b0ec878fc5c4eb838a18df5bf9fdc949df1122334455667788", 16),
          BigInt("CF9A30AC1F1F6AC0916F9FEF1919C595DEBE2EE80C85421210FDF05F1C6AF73AA9CAC881D0F91DB6D034A2BBADC1CF7FBCB2ECFA9D191D3A5016FB3FAD87038a18df5bf9fd3219C9", 16)
        )
      )

      val pOut = List(
        BigInt("f5f0eaa9ca3fd0c4e0d72a3471e4b71edaabe2d01c4b25e16715004ed91e663a1750707cc9f04430f19b995f4aba21b0ec878fc5c4eb838a18df5bf9fdc949df", 16),
        BigInt("A13E01494114C09800622A70288C432121CE70039D753CADD2E006E4D961CB27544C1481E5814BDCEB53BE6733D5E099795E5E81918ADDB058E22A9F24883F37", 16),
        BigInt("CF9A30AC1F1F6AC0916F9FEF1919C595DEBE2EE80C85421210FDF05F1C6AF73AA9CAC881D0F91DB6D034A2BBADC1CF7FBCB2ECFA9D191D3A5016FB3FAD8709C9", 16)
      )

      val e = sponge(CastByteArray(pIn(0)(0).toByteArray, 72), 1024, 576, 512)

      println(e.map(x => f"$x%02X").mkString(","))


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
          println(CastByteArray(rtlState_out.toByteArray, 512 / 8).map(x => f"$x%02X").mkString(","))
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

