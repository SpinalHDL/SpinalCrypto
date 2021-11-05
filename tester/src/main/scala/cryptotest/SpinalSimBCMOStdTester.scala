package cryptotest

import org.scalatest.funsuite.AnyFunSuite
import ref.symmetric.DES
import spinal.core._
import spinal.lib._
import spinal.crypto.symmetric.des.DESCore_Std
import spinal.crypto.symmetric._
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.{BigIntToHexString, CastByteArray}

import scala.collection.mutable.ArrayBuffer
import scala.util.Random


class DES_ECB_Tester() extends Component{

  val io = new Bundle{
    val ecb = slave(BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = 64,
      blockWidth = 64,
      useEncDec  = true,
      ivWidth    = -1
    )))
  }

  val core = new DESCore_Std()
  val chaining = ECB_Std(core.io.config, ENC_DEC)
  chaining.io.core <> core.io
  chaining.io.bcmo <> io.ecb
}


class DES_CBC_Tester() extends Component{

  val io = new Bundle{
    val ecb = slave(BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = 64,
      blockWidth = 64,
      useEncDec  = true,
      ivWidth    = 64
    )))
  }

  val core = new DESCore_Std()
  val chaining = CBC_Std(core.io.config, ENC_DEC)
  chaining.io.core <> core.io
  chaining.io.bcmo <> io.ecb
}


class DES_OFB_Tester() extends Component{

  val io = new Bundle{
    val ecb = slave(BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = 64,
      blockWidth = 64,
      useEncDec  = true,
      ivWidth    = 64
    )))
  }

  val core = new DESCore_Std()
  val chaining = OFB_Std(core.io.config, ENC_DEC, ENCRYPT)
  chaining.io.core <> core.io
  chaining.io.bcmo <> io.ecb
}

class DES_CFB_Tester() extends Component{

  val io = new Bundle{
    val ecb = slave(BCMO_Std_IO(BCMO_Std_Config(
      keyWidth   = 64,
      blockWidth = 64,
      useEncDec  = true,
      ivWidth    = 64
    )))
  }

  val core = new DESCore_Std()
  val chaining = CFB_Std(core.io.config, ENC_DEC, ENCRYPT)
  chaining.io.core <> core.io
  chaining.io.bcmo <> io.ecb
}

//class DES_CTR_Tester() extends Component{
//
//  val io = new Bundle{
//    val ecb = slave(BCMO_Std_IO(BCMO_Std_Generic(
//      keyWidth   = 64,
//      blockWidth = 64,
//      useEncDec  = true,
//      ivWidth    = 32
//    )))
//  }
//
//  val core = new DESCore_Std()
//  val chaining = CTR_Std(core.io.g, ENC_DEC)
//  chaining.io.core <> core.io
//  chaining.io.bcmo <> io.ecb
//}



class SpinalSimBCMOStdTester extends AnyFunSuite {

  test("ECB_DES") {
    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new DES_ECB_Tester()).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.ecb.cmd.valid  #= false
      dut.io.ecb.cmd.key    #= 0
      dut.io.ecb.cmd.block  #= 0
      dut.io.ecb.cmd.enc    #= false

      dut.clockDomain.waitActiveEdge()

      for(_ <- 0 until 10){

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


  test("CBC_DES"){
    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new DES_CBC_Tester()).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.ecb.cmd.valid  #= false
      dut.io.ecb.cmd.key    #= 0
      dut.io.ecb.cmd.block  #= 0
      dut.io.ecb.cmd.enc    #= false

      dut.clockDomain.waitActiveEdge()

      for(_ <- 0 until 10){

        val sizeBlock    = Random.nextInt(10) + 1

        val key          = BigInt(dut.io.ecb.cmd.key.getWidth, Random)
        val iv           = BigInt(dut.io.ecb.cmd.iv.getWidth, Random)
        val blockIn      = BigInt(dut.io.ecb.cmd.block.getWidth * sizeBlock, Random)
        val enc          = Random.nextBoolean()

        val ref_blockOut = DES.blockRaw(false)(
          key       = CastByteArray(key.toByteArray, 8),
          block     = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8),
          iv        = CastByteArray(iv.toByteArray, 8),
          enc       = enc,
          algoName  = "DES",
          chainning = "CBC",
          padding   = "noPadding"
        )

        var cntIteration = 0

        var blockIn_byte = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8)

        val rtlBlockOut = new ArrayBuffer[Byte]()

        while(cntIteration != sizeBlock){

          dut.io.ecb.cmd.valid  #= true
          dut.io.ecb.cmd.block  #= BigInt(0x00.toByte +: blockIn_byte.take(8))
          dut.io.ecb.cmd.key    #= BigInt(0x00.toByte +: CastByteArray(key.toByteArray, 8))
          dut.io.ecb.cmd.enc    #= enc
          dut.io.ecb.cmd.iv     #= BigInt(0x00.toByte +: CastByteArray(iv.toByteArray, 8))
          dut.io.ecb.cmd.mode   #= (if(cntIteration == 0) BCMO_Std_CmdMode.INIT else BCMO_Std_CmdMode.UPDATE)

          dut.clockDomain.waitActiveEdge()

          waitUntil(dut.io.ecb.rsp.valid.toBoolean == true)

          rtlBlockOut ++= CastByteArray(dut.io.ecb.rsp.block.toBigInt.toByteArray, 8)

          dut.clockDomain.waitActiveEdge()

          dut.io.ecb.cmd.valid #= false

          dut.clockDomain.waitActiveEdge()

          cntIteration += 1
          blockIn_byte = blockIn_byte.drop(8)
        }

//        println(BigIntToHexString(BigInt(rtlBlockOut.toArray)))

        assert(BigInt(rtlBlockOut.toArray) == BigInt(ref_blockOut) , s"Wrong result RTL ${BigIntToHexString(BigInt(rtlBlockOut.toArray))} !=  REF ${BigIntToHexString(BigInt(ref_blockOut.toArray))}")
      }
    }
  }



  test("OFB_DES"){
    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new DES_OFB_Tester()).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.ecb.cmd.valid  #= false
      dut.io.ecb.cmd.key    #= 0
      dut.io.ecb.cmd.block  #= 0
      dut.io.ecb.cmd.enc    #= false

      dut.clockDomain.waitActiveEdge()

      for(_ <- 0 until 10){

        val sizeBlock    = Random.nextInt(10) + 1

        val key          = BigInt(dut.io.ecb.cmd.key.getWidth, Random)
        val iv           = BigInt(dut.io.ecb.cmd.iv.getWidth, Random)
        val blockIn      = BigInt(dut.io.ecb.cmd.block.getWidth * sizeBlock, Random)
        val enc          = Random.nextBoolean()

        val ref_blockOut = DES.blockRaw(false)(
          key       = CastByteArray(key.toByteArray, 8),
          block     = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8),
          iv        = CastByteArray(iv.toByteArray, 8),
          enc       = enc,
          algoName  = "DES",
          chainning = "OFB",
          padding   = "noPadding"
        )

        var cntIteration = 0

        var blockIn_byte = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8)

        val rtlBlockOut = new ArrayBuffer[Byte]()

        while(cntIteration != sizeBlock){

          dut.io.ecb.cmd.valid  #= true
          dut.io.ecb.cmd.block  #= BigInt(0x00.toByte +: blockIn_byte.take(8))
          dut.io.ecb.cmd.key    #= BigInt(0x00.toByte +: CastByteArray(key.toByteArray, 8))
          dut.io.ecb.cmd.enc    #= enc
          dut.io.ecb.cmd.iv     #= BigInt(0x00.toByte +: CastByteArray(iv.toByteArray, 8))
          dut.io.ecb.cmd.mode   #= (if(cntIteration == 0) BCMO_Std_CmdMode.INIT else BCMO_Std_CmdMode.UPDATE)

          dut.clockDomain.waitActiveEdge()

          waitUntil(dut.io.ecb.rsp.valid.toBoolean == true)

          rtlBlockOut ++= CastByteArray(dut.io.ecb.rsp.block.toBigInt.toByteArray, 8)

          dut.clockDomain.waitActiveEdge()

          dut.io.ecb.cmd.valid #= false

          dut.clockDomain.waitActiveEdge()

          cntIteration += 1
          blockIn_byte = blockIn_byte.drop(8)
        }

//        println(BigIntToHexString(BigInt(rtlBlockOut.toArray)))

        assert(BigInt(rtlBlockOut.toArray) == BigInt(ref_blockOut) , s"Wrong result RTL ${BigIntToHexString(BigInt(rtlBlockOut.toArray))} !=  REF ${BigIntToHexString(BigInt(ref_blockOut.toArray))}")
      }
    }
  }


  test("CFB_DES"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new DES_CFB_Tester()).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.ecb.cmd.valid  #= false
      dut.io.ecb.cmd.key    #= 0
      dut.io.ecb.cmd.block  #= 0
      dut.io.ecb.cmd.enc    #= false

      dut.clockDomain.waitActiveEdge()

      for(_ <- 0 until 10){

        val sizeBlock    = Random.nextInt(10) + 1

        val key          = BigInt(dut.io.ecb.cmd.key.getWidth, Random)
        val iv           = BigInt(dut.io.ecb.cmd.iv.getWidth, Random)
        val blockIn      = BigInt(dut.io.ecb.cmd.block.getWidth * sizeBlock, Random)
        val enc          = Random.nextBoolean()

        val ref_blockOut = DES.blockRaw(false)(
          key       = CastByteArray(key.toByteArray, 8),
          block     = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8),
          iv        = CastByteArray(iv.toByteArray, 8),
          enc       = enc,
          algoName  = "DES",
          chainning = "CFB",
          padding   = "noPadding"
        )

        var cntIteration = 0

        var blockIn_byte = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8)

        val rtlBlockOut = new ArrayBuffer[Byte]()

        while(cntIteration != sizeBlock){

          dut.io.ecb.cmd.valid  #= true
          dut.io.ecb.cmd.block  #= BigInt(0x00.toByte +: blockIn_byte.take(8))
          dut.io.ecb.cmd.key    #= BigInt(0x00.toByte +: CastByteArray(key.toByteArray, 8))
          dut.io.ecb.cmd.enc    #= enc
          dut.io.ecb.cmd.iv     #= BigInt(0x00.toByte +: CastByteArray(iv.toByteArray, 8))
          dut.io.ecb.cmd.mode   #= (if(cntIteration == 0) BCMO_Std_CmdMode.INIT else BCMO_Std_CmdMode.UPDATE)

          dut.clockDomain.waitActiveEdge()

          waitUntil(dut.io.ecb.rsp.valid.toBoolean == true)

          rtlBlockOut ++= CastByteArray(dut.io.ecb.rsp.block.toBigInt.toByteArray, 8)

          dut.clockDomain.waitActiveEdge()

          dut.io.ecb.cmd.valid #= false

          dut.clockDomain.waitActiveEdge()

          cntIteration += 1
          blockIn_byte = blockIn_byte.drop(8)
        }

        //        println(BigIntToHexString(BigInt(rtlBlockOut.toArray)))

        assert(BigInt(rtlBlockOut.toArray) == BigInt(ref_blockOut) , s"Wrong result RTL ${BigIntToHexString(BigInt(rtlBlockOut.toArray))} !=  REF ${BigIntToHexString(BigInt(ref_blockOut.toArray))}")
      }
    }
  }


//
//  test("CTR_DES"){
//    val compileRTL_CTR_DES  = SimConfig.compile(new DES_CTR_Tester())
//    compileRTL_CTR_DES.doSim { dut =>
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
//      Suspendable.repeat(10){
//
//        val sizeBlock    = 2 //Random.nextInt(10) + 1
//
//        val key          = BigInt(dut.io.ecb.cmd.key.getWidth, Random)
//        val iv           = BigInt(dut.io.ecb.cmd.iv.getWidth , Random)
//        val blockIn      = BigInt(dut.io.ecb.cmd.block.getWidth * sizeBlock, Random)
//        val enc          = true //Random.nextBoolean()
//
//        val ref_blockOut = DES.blockRaw(false)(
//          key       = CastByteArray(key.toByteArray, 8),
//          block     = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8),
//          iv        = CastByteArray(iv.toByteArray, 8),
//          enc       = enc,
//          algoName  = "DES",
//          chainning = "CTR",
//          padding   = "noPadding"
//        )
//
//        var cntIteration = 0
//
//        var blockIn_byte = CastByteArray(blockIn.toByteArray, (dut.io.ecb.cmd.block.getWidth * sizeBlock) / 8)
//
//        val rtlBlockOut = new ArrayBuffer[Byte]()
//
//        while(cntIteration != sizeBlock){
//
//          dut.io.ecb.cmd.valid  #= true
//          dut.io.ecb.cmd.block  #= BigInt(0x00.toByte +: blockIn_byte.take(8))
//          dut.io.ecb.cmd.key    #= BigInt(0x00.toByte +: CastByteArray(key.toByteArray, 8))
//          dut.io.ecb.cmd.enc    #= enc
//          dut.io.ecb.cmd.iv     #= BigInt(0x00.toByte +: CastByteArray(iv.toByteArray, 8).takeRight(4))
//          dut.io.ecb.cmd.mode   #= (if(cntIteration == 0) BCMO_Std_CmdMode.INIT else BCMO_Std_CmdMode.UPDATE)
//
//          dut.clockDomain.waitActiveEdge()
//
//          waitUntil(dut.io.ecb.rsp.valid.toBoolean == true)
//
//          rtlBlockOut ++= CastByteArray(dut.io.ecb.rsp.block.toBigInt.toByteArray, 8)
//
//          dut.clockDomain.waitActiveEdge()
//
//          dut.io.ecb.cmd.valid #= false
//
//          dut.clockDomain.waitActiveEdge()
//
//          cntIteration += 1
//          blockIn_byte = blockIn_byte.drop(8)
//        }
//
//        //        println(BigIntToHexString(BigInt(rtlBlockOut.toArray)))
//
//        assert(BigInt(rtlBlockOut.toArray) == BigInt(ref_blockOut) , s"Wrong result RTL ${BigIntToHexString(BigInt(rtlBlockOut.toArray))} !=  REF ${BigIntToHexString(BigInt(ref_blockOut.toArray))}")
//      }
//    }
//  }
}

