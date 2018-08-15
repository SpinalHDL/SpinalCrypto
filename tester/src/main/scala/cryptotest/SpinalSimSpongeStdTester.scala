package cryptotest

import spinal.core._
import spinal.sim._
import spinal.core.sim._
import org.scalatest.FunSuite
import spinal.crypto.{BigIntToHexString, CastByteArray}
import spinal.crypto.construtor.{SpongeCoreCmd_Std, SpongeCoreRsp_Std, SpongeCore_Std}
import spinal.crypto.primitive.keccak.{FuncIO_Std, KeccakF_Std}
import spinal.lib._

import scala.util.Random


class SpinalSimSpongeStdTester extends FunSuite {


  def sponge(msg: Array[Byte], c: Int, r: Int, d: Int): Array[Byte] ={

    val msgCut = msg.sliding(r / 8, r / 8)
    val rReg = Array.fill(r / 8)(0x00.toByte)
    val cReg = Array.fill(c / 8)(0x00.toByte)

    /**
      * Absorbing
      */
    for(m <- msgCut){

      //println("msg", msg.length,  m.map(x => f"$x%02X").mkString(","))

      // XOR
      val xored = rReg.zip(m).map{case(a,b) => (a ^ b).toByte}
      //println("xor", xored.length, xored.map(x => f"$x%02X").mkString(","))

      // SHIFT
      val shift = (xored ++ cReg).slice(1, xored.length + cReg.length) :+ 0x00.toByte
      //println("shift", shift.length, shift.map(x => f"$x%02X").mkString(","))

      //println(rReg.length, cReg.length, shift.length)

      // COPY
      for(i <- 0 until rReg.length) rReg(i) = shift(i)
      for(i <- 0 until cReg.length) cReg(i) = shift(i + rReg.length - 1)
    }


    //println("rReg", rReg.length, rReg.map(x => f"$x%02X").mkString(","))
    //println("cReg", cReg.length, cReg.map(x => f"$x%02X").mkString(","))

    /**
      * Squeezing
      */
    val nbrSqueeze = scala.math.floor(d / r.toDouble).toInt
    val zReg = Array.fill((nbrSqueeze + 1) * (r / 8))(0x00.toByte)
    
    if(d > r){

      for(x <- 0 until nbrSqueeze){
        for(i <- 0 until rReg.length) zReg(i + x * (r/8)) = rReg(i)

        // SHIFT
        val shift = (rReg ++ cReg).slice(1, rReg.length + cReg.length) :+ 0x00.toByte
        //println("shift", shift.length, shift.map(x => f"$x%02X").mkString(","))

        // COPY
        for(i <- 0 until rReg.length) rReg(i) = shift(i)
        for(i <- 0 until cReg.length) cReg(i) = shift(i + rReg.length - 1)
      }

      for(i <- 0 until rReg.length) zReg(i + nbrSqueeze * (r/8)) = rReg(i)
    }



    return if(d > r) zReg.slice(0, d / 8) else rReg.slice(0, d / 8)
  }


  class FakeSponge(d: Int) extends Component {

    val io =  new Bundle{
      val init   = in Bool
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

      var iteration = 10

      // send differnt pattern
      while(iteration != 0){

        val nbrBlock = Random.nextInt(5) + 1

        val pIn = List.fill(nbrBlock)(BigInt(Array.fill(72)(Random.nextInt(256).toByte).map(x => f"$x%02X").mkString(""), 16))

        val refState_out = sponge(pIn.map(x => CastByteArray(x.toByteArray, 72)).reduce(_ ++ _), 1024, 576, 512)

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

        iteration -= 1
      }
    }
  }


  /**
    * Sponge with Squeezing
    */
  test("Sponge_withSqueezing"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new FakeSponge(1024)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      var iteration = 10

      // send differnt pattern
      while(iteration != 0){

        val nbrBlock = Random.nextInt(5) + 1

        val pIn = List.fill(nbrBlock)(BigInt(Array.fill(72)(Random.nextInt(256).toByte).map(x => f"$x%02X").mkString(""), 16))

        val refState_out = sponge(pIn.map(x => CastByteArray(x.toByteArray, 72)).reduce(_ ++ _), 1024, 576, 1024)

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

        iteration -= 1
      }
    }
  }
}

