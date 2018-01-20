package cryptotest

import org.scalatest.FunSuite
import ref.symmetric.DES
import spinal.core._
import spinal.lib._
import spinal.crypto.symmetric.des.DESCore_Std
import spinal.crypto.symmetric._
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.{BigIntToHexString, CastByteArray}

import scala.util.Random



class SpinalSimBCMOStdTester extends FunSuite {

  class DES_ECB_Tester() extends Component{

    val io = new Bundle{
      val ecb = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = true,
        ivWidth    = -1
      )))
    }

    val core = new DESCore_Std()
    val chaining = ECB_Std(core.io.g, ENC_DEC)
    chaining.io.core <> core.io
    chaining.io.bcmo <> io.ecb
  }

  class DES_CBC_Tester() extends Component{

    val io = new Bundle{
      val ecb = slave(BCMO_Std_IO(BCMO_Std_Generic(
        keyWidth   = 64,
        blockWidth = 64,
        useEncDec  = true,
        ivWidth    = 64
      )))
    }

    val core = new DESCore_Std()
    val chaining = CBC_Std(core.io.g, ENC_DEC)
    chaining.io.core <> core.io
    chaining.io.bcmo <> io.ecb
  }


  // RTL to simulate
  val compiledRTL_ECB_DES = SimConfig.compile(new DES_ECB_Tester())
  val compileRTL_CBC_DES  = SimConfig.compile(new DES_CBC_Tester())


  test("ECB_DES") {

    compiledRTL_ECB_DES.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.ecb.cmd.valid  #= false
      dut.io.ecb.cmd.key    #= 0
      dut.io.ecb.cmd.block  #= 0
      dut.io.ecb.cmd.enc    #= false

      dut.clockDomain.waitActiveEdge()

      Suspendable.repeat(10){

        val key          = BigInt(dut.io.ecb.cmd.key.getWidth, Random)
        val blockIn      = BigInt(dut.io.ecb.cmd.block.getWidth, Random)
        val enc          = Random.nextBoolean()
        val ref_blockOut = DES.block(false)(key, blockIn, enc)

        dut.io.ecb.cmd.valid  #= true
        dut.io.ecb.cmd.block  #= blockIn
        dut.io.ecb.cmd.key    #= key
        dut.io.ecb.cmd.enc    #= enc

        waitUntil(dut.io.ecb.rsp.valid.toBoolean == true)

        val rtlBlock_out = dut.io.ecb.rsp.block.toBigInt

        assert(BigInt(rtlBlock_out.toByteArray.takeRight(dut.io.ecb.cmd.block.getWidth / 8)) == BigInt(ref_blockOut.toByteArray.takeRight(dut.io.ecb.cmd.block.getWidth / 8)) , s"Wrong result RTL ${BigIntToHexString(rtlBlock_out)} !=  REF ${BigIntToHexString(ref_blockOut)}")

        dut.clockDomain.waitActiveEdge()

        dut.io.ecb.cmd.valid #= false

        dut.clockDomain.waitActiveEdge()

      }
    }
  }


//  test("CBC_DES"){
//    compileRTL_CBC_DES.doSim { dut =>
//
//      dut.clockDomain.forkStimulus(2)
//
//      // initialize value
//      dut.io.ecb.cmd.valid  #= false
//      dut.io.ecb.cmd.key    #= 0
//      dut.io.ecb.cmd.block  #= 0
//      dut.io.ecb.cmd.enc    #= false
//
//      dut.clockDomain.waitActiveEdge()
//
//      Suspendable.repeat(1){
//
//        val key          = BigInt(dut.io.ecb.cmd.key.getWidth, Random)
//        val blockIn      = BigInt(dut.io.ecb.cmd.block.getWidth * 3, Random)
//        val enc          = Random.nextBoolean()
//        val ref_blockOut = DES.blockWithChaining(true)(key, blockIn, (dut.io.ecb.cmd.block.getWidth * 3) / 8,  enc, "CBC")
//
//
//        var iteration = 3
//
//        var blockIn_byte = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * 3) / 8)
//
//        while(iteration != 0){
//
//          dut.io.ecb.cmd.valid  #= true
//          dut.io.ecb.cmd.block  #= BigInt(0x00.toByte +: blockIn_byte.take(8))
//          dut.io.ecb.cmd.key    #= key
//          dut.io.ecb.cmd.enc    #= enc
//
//          println(BigIntToHexString(BigInt(0x00.toByte +: blockIn_byte.take(8))))
//
//          waitUntil(dut.io.ecb.rsp.valid.toBoolean == true)
//
//          val rtlBlock_out = dut.io.ecb.rsp.block.toBigInt
//
//          //        assert(BigInt(rtlBlock_out.toByteArray.takeRight(dut.io.ecb.cmd.block.getWidth / 8)) == BigInt(ref_blockOut.toByteArray.takeRight(dut.io.ecb.cmd.block.getWidth / 8)) , s"Wrong result RTL ${BigIntToHexString(rtlBlock_out)} !=  REF ${BigIntToHexString(ref_blockOut)}")
//
//          println(BigIntToHexString(rtlBlock_out))
//
//          dut.clockDomain.waitActiveEdge()
//
//          dut.io.ecb.cmd.valid #= false
//
//          dut.clockDomain.waitActiveEdge()
//
//          iteration -= 1
//          blockIn_byte = blockIn_byte.drop(8)
//        }
//      }
//    }
//  }

}
