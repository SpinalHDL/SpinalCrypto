package cryptotest

import spinal.core.SpinalConfig
import spinal.core.sim.SimConfig
import org.scalatest.funsuite.AnyFunSuite
import spinal.core._
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.core.sim._
import spinal.crypto.symmetric.twofish._




class SpinalSimTwoFishCoreStdTester extends AnyFunSuite {

  val ref_key_128     = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("00000000000000000000000000000000", 16),
    BigInt("9F589F5CF6122C32B6BFEC2F2AE8C35A", 16)
  )

  val ref_plain_128  = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("9F589F5CF6122C32B6BFEC2F2AE8C35A", 16),
    BigInt("D491DB16E7B1C39E86CB086B789F5419", 16)
  )

  val ref_cipher_128  = List(
    BigInt("9F589F5CF6122C32B6BFEC2F2AE8C35A", 16),
    BigInt("D491DB16E7B1C39E86CB086B789F5419", 16),
    BigInt("019F9809DE1711858FAAC3A3BA20FBC3", 16)
  )


  val ref_key_192     = List(
    BigInt("000000000000000000000000000000000000000000000000", 16),
    BigInt("88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44", 16),
    BigInt("39DA69D6BA4997D585B6DC073CA341B288B2B2706B105E36", 16)
  )

  val ref_plain_192  = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("39DA69D6BA4997D585B6DC073CA341B2", 16),
    BigInt("182B02D81497EA45F9DAACDC29193A65", 16)
  )

  val ref_cipher_192  = List(
    BigInt("EFA71F788965BD4453F860178FC19101", 16),
    BigInt("182B02D81497EA45F9DAACDC29193A65", 16),
    BigInt("7AFF7A70CA2FF28AC31DD8AE5DAAAB63", 16)
  )


  val ref_key_256     = List(
    BigInt("0000000000000000000000000000000000000000000000000000000000000000", 16),
    BigInt("D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F", 16)
  )

  val ref_plain_256   = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("90AFE91BB288544F2C32DC239B2635E6", 16)
  )

  val ref_cipher_256  = List(
    BigInt("57FF739D4DC92C1BD7FC01700CC8216F", 16),
    BigInt("6CB4561C40BF0A9705931CB6D408E7FA", 16)
  )

  /**
    * Test - TwoFish (128-bit)
    */
  test("TwoFishCoreStd_128"){
    SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(6).compile(new TwofishCore_Std(128 bits)).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.cmd.valid #= false
      dut.io.cmd.block.randomize()
      dut.io.cmd.key.randomize()
      if (dut.io.config.useEncDec) dut.io.cmd.enc.randomize()

      dut.clockDomain.waitActiveEdge()

      for ((key, plain, cipher) <- (ref_key_128, ref_plain_128, ref_cipher_128).zipped) {


        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = true,
          blockIn     = plain,
          keyIn       = key)((a: BigInt, b: BigInt, c: Boolean) => cipher)

        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = false,
          blockIn     = cipher,
          keyIn       = key)((a: BigInt, b: BigInt, c: Boolean) => plain)

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge(40)
    }
  }


  /**
    * Test - TwoFish (192-bit)
    */
  test("TwoFishCoreStd_192"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(6).compile(new TwofishCore_Std(192 bits)).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.cmd.valid #= false
      dut.io.cmd.block.randomize()
      dut.io.cmd.key.randomize()
      if (dut.io.config.useEncDec) dut.io.cmd.enc.randomize()

      dut.clockDomain.waitActiveEdge()

      for ((key, plain, cipher) <- (ref_key_192, ref_plain_192, ref_cipher_192).zipped) {


        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = true,
          blockIn     = plain,
          keyIn       = key)((a: BigInt, b: BigInt, c: Boolean) => cipher)

        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = false,
          blockIn     = cipher,
          keyIn       = key)((a: BigInt, b: BigInt, c: Boolean) => plain)

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge(40)
    }
  }


  /**
    * Test - TwoFish (256-bit)
    */
  test("TwoFishCoreStd_256"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(6).compile(new TwofishCore_Std(256 bits)).doSim { dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.cmd.valid #= false
      dut.io.cmd.block.randomize()
      dut.io.cmd.key.randomize()
      if (dut.io.config.useEncDec) dut.io.cmd.enc.randomize()

      dut.clockDomain.waitActiveEdge()

      for ((key, plain, cipher) <- (ref_key_256, ref_plain_256, ref_cipher_256).zipped) {


        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = true,
          blockIn     = plain,
          keyIn       = key)((a: BigInt, b: BigInt, c: Boolean) => cipher)

        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = false,
          blockIn     = cipher,
          keyIn       = key)((a: BigInt, b: BigInt, c: Boolean) => plain)

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge(40)
    }
  }



}
