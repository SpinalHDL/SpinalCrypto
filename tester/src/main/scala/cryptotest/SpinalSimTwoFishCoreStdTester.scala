package cryptotest

import spinal.core.SpinalConfig
import spinal.core.sim.SimConfig
import org.scalatest.FunSuite
import spinal.core._
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.core.sim._
import spinal.crypto.symmetric.twofish._




class SpinalSimTwoFishCoreStdTester extends FunSuite {


  /*
   * 128-bit key =>  ref patterns
   */
  val ref_key_128 = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("00000000000000000000000000000000", 16),
    BigInt("9F589F5CF6122C32B6BFEC2F2AE8C35A", 16),
    BigInt("137A24CA47CD12BE818DF4D2F4355960", 16),
    BigInt("6600522E97AEB3094ED5F92AFCBCDD10", 16)
  )

  val ref_plain_128 = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("9F589F5CF6122C32B6BFEC2F2AE8C35A", 16),
    BigInt("D491DB16E7B1C39E86CB086B789F5419", 16),
    BigInt("BCA724A54533C6987E14AA827952F921", 16),
    BigInt("34C8A5FB2D3D08A170D120AC6D26DBFA", 16)
  )

  val ref_cipher_128 = List(
    BigInt("9F589F5CF6122C32B6BFEC2F2AE8C35A", 16),
    BigInt("D491DB16E7B1C39E86CB086B789F5419", 16),
    BigInt("019F9809DE1711858FAAC3A3BA20FBC3", 16),
    BigInt("6B459286F3FFD28D49F15B1581B08E42", 16),
    BigInt("28530B358C1B42EF277DE6D4407FC591", 16)
  )


  /*
   * 192-bit key =>  ref patterns
   */
  val ref_key_192 = List(
    BigInt("000000000000000000000000000000000000000000000000", 16),
    BigInt("88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44", 16),
    BigInt("39DA69D6BA4997D585B6DC073CA341B288B2B2706B105E36", 16),
    BigInt("182B02D81497EA45F9DAACDC29193A6539DA69D6BA4997D5", 16),
    BigInt("AE8109BFDA85C1F2C5038B34ED691BFF3AF6F7CE5BD35EF1", 16)
  )

  val ref_plain_192 = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("39DA69D6BA4997D585B6DC073CA341B2", 16),
    BigInt("182B02D81497EA45F9DAACDC29193A65", 16),
    BigInt("7AFF7A70CA2FF28AC31DD8AE5DAAAB63", 16),
    BigInt("893FD67B98C550073571BD631263FC78", 16)
  )

  val ref_cipher_192 = List(
    BigInt("EFA71F788965BD4453F860178FC19101", 16),
    BigInt("182B02D81497EA45F9DAACDC29193A65", 16),
    BigInt("7AFF7A70CA2FF28AC31DD8AE5DAAAB63", 16),
    BigInt("D1079B789F666649B6BD7D1629F1F77E", 16),
    BigInt("16434FC9C8841A63D58700B5578E8F67", 16)
  )


  /*
   * 256-bit key =>  ref patterns
   */
  val ref_key_256 = List(
    BigInt("0000000000000000000000000000000000000000000000000000000000000000", 16),
    BigInt("D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F", 16),
    BigInt("E69465770505D7F80EF68CA38AB3A3D63059D6D61753B958D92F4781C8640E58", 16),
    BigInt("DC096BCD99FC72F79936D4C748E75AF75AB67A5F8539A4A5FD9F0373BA463466", 16),
    BigInt("2E2158BC3E5FC714C1EEECA0EA696D48D2DED73E59319A8138E0331F0EA149EA", 16)
  )

  val ref_plain_256 = List(
    BigInt("00000000000000000000000000000000", 16),
    BigInt("90AFE91BB288544F2C32DC239B2635E6", 16),
    BigInt("5AB67A5F8539A4A5FD9F0373BA463466", 16),
    BigInt("C5A3E7CEE0F1B7260528A68FB4EA05F2", 16),
    BigInt("248A7F3528B168ACFDD1386E3F51E30C", 16)
  )

  val ref_cipher_256 = List(
    BigInt("57FF739D4DC92C1BD7FC01700CC8216F", 16),
    BigInt("6CB4561C40BF0A9705931CB6D408E7FA", 16),
    BigInt("DC096BCD99FC72F79936D4C748E75AF7", 16),
    BigInt("43D5CEC327B24AB90AD34A79D0469151", 16),
    BigInt("431058F4DBC7F734DA4F02F04CC4F459", 16)
  )


  /**
    * Twofish test template
    */
  def twofish_test(dut: TwofishCore_Std, ref_key: List[BigInt], ref_plain: List[BigInt], ref_cipher: List[BigInt]): Unit = {
    dut.clockDomain.forkStimulus(2)

    // initialize value
    dut.io.cmd.valid #= false
    dut.io.cmd.block.randomize()
    dut.io.cmd.key.randomize()
    if (dut.io.config.useEncDec) dut.io.cmd.enc.randomize()

    dut.clockDomain.waitActiveEdge()

    for ((key, plain, cipher) <- (ref_key, ref_plain, ref_cipher).zipped) {

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


  /**
    * Test - TwoFish (128-bit)
    */
  test("TwoFishCoreStd_128"){
    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new TwofishCore_Std(128 bits)).doSim { dut =>

      twofish_test(dut, ref_key_128, ref_plain_128, ref_cipher_128)
    }
  }


  /**
    * Test - TwoFish (192-bit)
    */
  test("TwoFishCoreStd_192"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new TwofishCore_Std(192 bits)).doSim { dut =>

      twofish_test(dut, ref_key_192, ref_plain_192, ref_cipher_192)
    }
  }


  /**
    * Test - TwoFish (256-bit)
    */
  test("TwoFishCoreStd_256"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new TwofishCore_Std(256 bits)).doSim { dut =>

      twofish_test(dut, ref_key_256, ref_plain_256, ref_cipher_256)
    }
  }

}
