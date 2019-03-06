package cryptotest

import spinal.core.SpinalConfig
import spinal.core.sim.SimConfig
import org.scalatest.FunSuite
import ref.symmetric.RefTwoFish
import spinal.core._
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.sim._
import spinal.core.sim._
import spinal.crypto.symmetric.twofish._

import scala.util.Random



class SpinalSimTwoFishCoreStdTester extends FunSuite {

  val ref_key_256     = List(
    BigInt("B00DACFFF50660170A43C7277D2745902C8E0854AEAF451096A96A96EB1F010E", 16),
    BigInt("563DA55F0825E3450F886BD32CF18DC772214D008E095877AD2189393EEC955D", 16),
    BigInt("743B0025E35CD475636372864876A04EA0500FBA8F785855E3A415EA5E178374", 16),
    BigInt("3EC201A67054161C9746126B501E6F1CA800A9B20C59AC232511362F8824E7FE", 16),
    BigInt("8787FE585483C5148AA58D5F6D74A814D99955763C9916EB74E6006A954845DE", 16),
    BigInt("1C59544605D493742D79F9D8CD60486D568D46E10CFFE26ECFBF84DB480C7CF5", 16),
    BigInt("D9101783D3D7E5C23569C524219DAD6B32B67D8A117A01FCA2B4A515E47888F8", 16),
    BigInt("290B038DAECCA6270927DC15CD463AF1FC9DA03A0967B1EC724B28F53EB4AE2C", 16),
    BigInt("BFA53A8D373227B872A4D99BD328819A19148300ED046CD6761453502CE0A454", 16),
    BigInt("86F5EF344BDC69D03C07D76E0CC7F21D8FB4E6EE776CB08B539DB6627DF9CA89", 16),
    BigInt("03B27F93CFE0F97D77BE7229EE84EAE6853601927D769AFCF4AFD8CD9C6D8618", 16),
    BigInt("7CC66BB6216FB1D91E0B1E7D67AF02C1DB3FBF211A1B5865FABF5EE08042DFE2", 16)
  )

  val ref_plain_256   = List(
    BigInt("D857791DCB86A5B163F117B343C2C25E", 16),
    BigInt("593A2DA60CB845F3862681631A3EF178", 16),
    BigInt("4F605AE3419C74758DB0BD9B01652C17", 16),
    BigInt("7176658B0088A3CA6BE280C0C945EED4", 16),
    BigInt("96B21E268D0FE312DC8CC2423105C0F3", 16),
    BigInt("B152BA5F12AB00EC3036DD4DC6CA796F", 16),
    BigInt("97AD799973D0DFEF7321CF86C9E09A67", 16),
    BigInt("A0E0CCC34731335D9B982A5F1B21CBD2", 16),
    BigInt("7E72264880BC6517FD72CC1AA5017AE3", 16),
    BigInt("5419D35470B981318FC5C92FF4368FD8", 16),
    BigInt("9E60D4D38027A9801297AF60ED0C08B4", 16),
    BigInt("2B7DECE3A2715117C3EC4996CA0080D0", 16)
  )

  val ref_cipher_256  = List(
    BigInt("5249276be694b468c33f2bc156cd0721", 16),
    BigInt("caff9811b10b8e91464eb4e0fb4ad178", 16),
    BigInt("2c7dfc8da3163976428f43be86714b83", 16),
    BigInt("8abb828e86a1bd9fca91f1e1beb846da", 16),
    BigInt("07ba4270db20881f1b6a6aa6d0a7b22c", 16),
    BigInt("5ac2812dd41af19628b40a7aff39a3b9", 16),
    BigInt("cca8b6888e6e9c8bd31a4d3129f3b1a8", 16),
    BigInt("430c45c9b2810021016e258ee585552e", 16),
    BigInt("460ba7300a0665554f6c7cab2bf81f82", 16),
    BigInt("8ef41279949290f2b87fed3436d0310c", 16),
    BigInt("3ef1e08388c54406a143ff888e4da248", 16),
    BigInt("aeb6ccd3c3e1bb91b4620bd72e2faca2", 16)
  )

  /**
    * Test - TwoFish (256-bit)
    */
  test("TwoFishCoreStd_256"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(6).compile(new TwofishCore_Std()).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.cmd.valid #= false
      dut.io.cmd.block.randomize()
      dut.io.cmd.key #= 0
      if(dut.io.config.useEncDec) dut.io.cmd.enc.randomize()

      dut.clockDomain.waitActiveEdge()

  /*    for((key, plain, cipher) <- (ref_key_256, ref_plain_256, ref_cipher_256).zipped){


        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = true,
          blockIn     = plain,
          keyIn       = key)((a: BigInt, b: BigInt, c:Boolean) => cipher)

        SymmetricCryptoBlockIOSim.doSim(
          dut         = dut.io,
          clockDomain = dut.clockDomain,
          enc         = false,
          blockIn     = cipher,
          keyIn       = key)((a: BigInt, b: BigInt, c:Boolean) => plain)

      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false
*/
      dut.clockDomain.waitActiveEdge(20)
    }
  }



  test("test_Hoperaton"){

    class ComponentHOperation extends Component {
      val io = new Bundle {
        val input  = in Bits(32 bits)
        val output = out Bits(32 bits)
        val s0, s1 = in Bits(32 bits)
      }

      val h = new HOperation()
      h.io.input := io.input
      h.io.s0    := io.s0
      h.io.s1    := io.s1
      io.output  := RegNext(h.io.output)
    }

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(3).compile(new ComponentHOperation).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.input.randomize()
      dut.io.s0.randomize()
      dut.io.s1.randomize()

      dut.clockDomain.waitActiveEdge(2)

      for(i <- 0 until 50){

        val ioInput = if (i == 0)  0x00 else Random.nextInt(45000)
        val s0 = 0
        val s1 = 0

        dut.io.input #= ioInput
        dut.io.s0 #= s0
        dut.io.s1 #= s1

        dut.clockDomain.waitSampling(2)

        val rtlResult = dut.io.output.toBigInt.toInt
        val model =  RefTwoFish.h(ioInput, s0, s1)

        println(f"Input ${ioInput}%08X => Model ${model}%08X , rtl ${rtlResult}%08X")

        dut.clockDomain.waitSampling()

    //    assert(model == rtlResult)
      }

      dut.clockDomain.waitActiveEdge(10)
    }
  }

  /**
    * Test Q0 et Q1
    */
  test("test_Qoperation"){

    class ComponentQOperation(val number: Int) extends Component{
      val io = new Bundle{
        val input = in Bits(8 bits)
        val output = out Bits(8 bits)
      }

      val q = new Qoperation(number)
      q.io.input := io.input
      io.output  := RegNext(q.io.output)
    }

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).withWave(2).compile(new ComponentQOperation(1)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.input.randomize()

      dut.clockDomain.waitActiveEdge(2)

      for(i <- 0 until 50){

        val random = if (i == 0)  0 else Random.nextInt(255)

        dut.io.input #= random

        dut.clockDomain.waitSampling(2)

        val rtlResult = dut.io.output.toBigInt.toByte
        val model = if(dut.number == 0) RefTwoFish.q0(random.toByte) else RefTwoFish.q1(random.toByte)

        println(f"Input ${random}%02X => Model ${model}%02X , rtl ${rtlResult}%02X")

        dut.clockDomain.waitSampling()

        assert(model == rtlResult)
      }

      dut.clockDomain.waitActiveEdge(10)
    }
  }

}
