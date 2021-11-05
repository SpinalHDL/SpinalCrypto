package cryptotest



import org.scalatest.funsuite.AnyFunSuite
import ref.hash.SHA2
import spinal.core.SpinalConfig
import spinal.crypto.hash.BIG_endian
import spinal.crypto.hash.sim.{HashEngineIOsim, HashIOsim}

import spinal.core.sim._
import spinal.crypto.hash.sha2._

/**
  * Test SHA2Core_Std
  */
class SpinalSimSHA2CoreStdTester extends AnyFunSuite {

  val NBR_ITERATION = 100

  /**
    * SHA2CoreStd_256
    */
  test("SHA2CoreStd_256") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Core_Std(SHA2_256))

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, BIG_endian )(SHA2.digest("SHA-256"))
      }
    }
  }

  /**
    *  SHA2CoreStd_512
    */
  test("SHA2CoreStd_512") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Core_Std(SHA2_512))

    compiledRTL.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      HashIOsim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for(i <- 0 to NBR_ITERATION){
        HashIOsim.doSim(dut.io, dut.clockDomain, i, BIG_endian )(SHA2.digest("SHA-512"))
      }
    }
  }
}


/**
  * Test Sha2Engine_Std
  *
  */
class SpinalSimSHA2EngineStdTester extends AnyFunSuite {

  /**
    * SHA2Engine_Std_224
    */
  test("SHA2Engine_Std_224") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Engine_Std(SHA2_224))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val messages = List(
        List(BigInt("61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16))
      )

      val refDigest = List(
        BigInt("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", 16)
      )

      for((ref, msg) <- refDigest.zip(messages)){

        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)
      }
    }
  }


  /**
    * SHA2Engine_Std_256
    */
  test("SHA2Engine_Std_256") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Engine_Std(SHA2_256))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val messages = List(
        List(BigInt("61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16)),
        List(BigInt("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000", 16),
          BigInt("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0", 16))
      )

      val refDigest = List(
        BigInt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 16),
        BigInt("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 16)
      )

      for((ref, msg) <- refDigest.zip(messages)){
        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)
      }

    }
  }

  /**
    * SHA2Engine_Std_384
    */
  test("SHA2Engine_Std_384") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Engine_Std(SHA2_384))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val messages = List(
        List(BigInt("6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16))
      )

      val refDigest = List(
        BigInt("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", 16)
      )

      for((ref, msg) <- refDigest.zip(messages)){
        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)
      }
    }
  }

  /**
    * SHA2Engine_Std_512
    */
  test("SHA2Engine_Std_512") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Engine_Std(SHA2_512))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val messages = List(
        List(BigInt("6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16)),
        List(BigInt("61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f70717273747580000000000000000000000000000000", 16),
             BigInt("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000380", 16))
      )

      val refDigest = List(
        BigInt("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 16),
        BigInt("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", 16)

      )

      for((ref, msg) <- refDigest.zip(messages)){
        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)
      }
    }
  }

  /**
    * SHA2Engine_Std_512_224
    */
  test("SHA2Engine_Std_512_224") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Engine_Std(SHA2_512_224))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val messages = List(
        List(BigInt("6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16))
      )

      val refDigest = List(
        BigInt("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", 16)
      )

      for((ref, msg) <- refDigest.zip(messages)){
        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)
      }
    }
  }

  /**
    * SHA2Engine_Std_512_256
    */
  test("SHA2Engine_Std_512_256") {

    val compiledRTL = SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new SHA2Engine_Std(SHA2_512_256))

    compiledRTL.doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      dut.io.cmd.valid #= false
      dut.io.cmd.message.randomize()
      dut.io.init #= false

      dut.clockDomain.waitActiveEdge()

      val messages = List(
        List(BigInt("6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", 16))
      )

      val refDigest = List(
        BigInt("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", 16)
      )


      for((ref, msg) <- refDigest.zip(messages)){

        HashEngineIOsim.doSim(dut.io, dut.clockDomain, msg, ref)

      }
    }
  }
}

