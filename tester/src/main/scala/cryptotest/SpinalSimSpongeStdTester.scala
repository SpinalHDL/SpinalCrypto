package cryptotest

import spinal.core._
import spinal.core.sim._
import org.scalatest.funsuite.AnyFunSuite
import ref.constructor.Sponge
import spinal.crypto.{BigIntToHexString, CastByteArray}
import spinal.crypto.construtor.{SpongeCoreCmd_Std, SpongeCoreRsp_Std, SpongeCore_Std}
import spinal.lib._

import scala.util.Random


class SpinalSimSpongeStdTester extends AnyFunSuite {

  val NBR_ITERATION = 10


  class FakeSponge(d: Int) extends Component {

    val io =  new Bundle{
      val init   = in Bool()
      val cmd    = slave(Stream(Fragment(SpongeCoreCmd_Std(576))))
      val rsp    = master(Flow(SpongeCoreRsp_Std(d)))
    }

    val sponge = new SpongeCore_Std(1024, 576, d)
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


  /**
    * Sponge without squeezing
    */
  test("Sponge_noSqueezing"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new FakeSponge(512)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)


      // send differnt pattern
      for(_ <- 0 to NBR_ITERATION){

        val nbrBlock = Random.nextInt(5) + 1

        val pIn = List.fill(nbrBlock)(BigInt(Array.fill(72)(Random.nextInt(256).toByte).map(x => f"$x%02X").mkString(""), 16))

        val refState_out = Sponge(pIn.map(x => CastByteArray(x.toByteArray, 72)).reduce(_ ++ _), 1024, 576, 512)

        var indexBlock = 0

        // initialize value
        dut.io.init       #= true
        dut.io.cmd.last   #= false
        dut.io.cmd.valid  #= false
        dut.io.cmd.n.randomize()

        dut.clockDomain.waitActiveEdge()

        dut.io.init #= false

        // Send all block in the sponge
        while(indexBlock != pIn.length){

          dut.clockDomain.waitActiveEdge()

          dut.io.cmd.last  #= (indexBlock == pIn.length - 1)
          dut.io.cmd.valid #= true
          dut.io.cmd.n     #= pIn(indexBlock)

          dut.clockDomain.waitActiveEdgeWhere(dut.io.cmd.ready.toBoolean)
          dut.io.cmd.valid #= false

          if(indexBlock == pIn.length - 1){

            val rtlState_out = BigInt(dut.io.rsp.z.toBigInt.toByteArray.takeRight(dut.io.rsp.z.getWidth / 8))

            assert(CastByteArray(rtlState_out.toByteArray, 512 / 8).sameElements(refState_out), s"Wrong result RTL ${BigIntToHexString(rtlState_out)} !=  REF ${refState_out.map(x => f"$x%02X").mkString("")}")
          }
          indexBlock += 1
        }

        dut.clockDomain.waitActiveEdge(5)

      }
    }
  }


  /**
    * Sponge with Squeezing
    */
  test("Sponge_withSqueezing"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new FakeSponge(1024)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)


      // send differnt pattern
      for(_ <- 0 to NBR_ITERATION){

        val nbrBlock = Random.nextInt(5) + 1

        val pIn = List.fill(nbrBlock)(BigInt(Array.fill(72)(Random.nextInt(256).toByte).map(x => f"$x%02X").mkString(""), 16))

        val refState_out = Sponge(pIn.map(x => CastByteArray(x.toByteArray, 72)).reduce(_ ++ _), 1024, 576, 1024)

        var indexBlock = 0

        // initialize value
        dut.io.init       #= true
        dut.io.cmd.last   #= false
        dut.io.cmd.valid  #= false
        dut.io.cmd.n.randomize()

        dut.clockDomain.waitActiveEdge()

        dut.io.init #= false

        // Send all block in the sponge
        while(indexBlock != pIn.length){

          dut.clockDomain.waitActiveEdge()

          dut.io.cmd.last  #= (indexBlock == pIn.length - 1)
          dut.io.cmd.valid #= true
          dut.io.cmd.n     #= pIn(indexBlock)

          dut.clockDomain.waitActiveEdgeWhere(dut.io.cmd.ready.toBoolean)
          dut.io.cmd.valid #= false

          if(indexBlock == pIn.length - 1){

            val rtlState_out = BigInt(dut.io.rsp.z.toBigInt.toByteArray.takeRight(dut.io.rsp.z.getWidth / 8))

            assert(CastByteArray(rtlState_out.toByteArray, 1024 / 8).sameElements(refState_out), s"Wrong result RTL ${BigIntToHexString(rtlState_out)} !=  REF ${refState_out.map(x => f"$x%02X").mkString("")}")
          }
          indexBlock += 1
        }

        dut.clockDomain.waitActiveEdge(5)

      }
    }
  }
}

