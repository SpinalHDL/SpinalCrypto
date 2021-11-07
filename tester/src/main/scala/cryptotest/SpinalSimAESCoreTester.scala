package cryptotest

import org.scalatest.funsuite.AnyFunSuite
import ref.symmetric.AES
import spinal.crypto.symmetric.aes.AESCore_Std
import spinal.crypto.symmetric.sim.SymmetricCryptoBlockIOSim
import spinal.core._
import spinal.core.sim._

import scala.util.Random


class SpinalSimAESCoreTester extends AnyFunSuite {

  val NBR_ITERATION = 20

  val ref_key_192     = List(
    BigInt("6ABBBC50D08AFC199FBC016526C4283B8FEC6D2B885FC561", 16),
    BigInt("A2ED76AFC3F9D4E7681E713F93B61BD155D1A2D7DE357BDD", 16),
    BigInt("53F68E3E567773D3F3547CDBACC6A30E088351E6452A53C3", 16),
    BigInt("B1899353221201AE06BC2727B7C9C7BE68E32E5CAB155729", 16),
    BigInt("EE0009BB08CCC77C279D7B38DC3758C9F299B26BE3BF9F66", 16),
    BigInt("00480C389D551E03EB87031102C6661A8DB7CDDBC30BB827", 16),
    BigInt("76A9A31C04226A885BD42FDFAA1C04DDC2E1488B15C961A9", 16),
    BigInt("21F3EB61A808BA8F4C35F56A9F105258959C9054CD4DDF8C", 16),
    BigInt("22E73418B0C00D26E196A808E5DF6B746CC50944A2359B4F", 16),
    BigInt("26328555A340EBAE7F0656A1B418493DA49C2C83D4705705", 16),
    BigInt("EA24B53818A6CBCC209CD36321D14B3A688A43F2122B071E", 16),
    BigInt("8652D785134E52DF8E5EC717A4344DEA3BF700CF319294A2", 16)
  )

  val ref_plain_192   = List(
    BigInt("A7B8FAAF3AE1242BBC78855109D277EA", 16),
    BigInt("2D234D2A0A3657DBD18A9527EBE33594", 16),
    BigInt("46205D6E3C11C5A7601040848512CE06", 16),
    BigInt("1D3AC9C4FB2967EA212A60045442FECE", 16),
    BigInt("6A7C9EFFB8346D4A0B4BB4C986648BD2", 16),
    BigInt("D4F16E958EE55AED23293F87E64CF63E", 16),
    BigInt("50F4895D300A1EB0912D011511281540", 16),
    BigInt("7C96258BC956A8F95062E4499F0FF4D5", 16),
    BigInt("7A0C2875BF800219E89D10E9A28342AC", 16),
    BigInt("949E1A9E0C678AFFFDD21EEE3C04F0D4", 16),
    BigInt("1E3D029ACD08E4DB74B3B17D4BEB4927", 16),
    BigInt("EF55D405140C2ADBC8590114126CEEC9", 16)
  )

  val ref_cipher_192  = List(
    BigInt("c93d735113fede10a9101a0344dae6a9", 16),
    BigInt("0c278804e7fe30ebcc75e93316532e50", 16),
    BigInt("ba92d96c42cd8e515406b64c88de8a0c", 16),
    BigInt("eed933e8631e53527bc6e239654bb4c6", 16),
    BigInt("8988e76d9c23f1b55177907745e3c1c6", 16),
    BigInt("06b23321b8e220b38fbf7e6b636043e5", 16),
    BigInt("68c276caa8afb0c85d85e460948c26b1", 16),
    BigInt("8f802592668cf79f19444f5b192e89fa", 16),
    BigInt("6eaa516f86846fb4e5b839263d432272", 16),
    BigInt("76489285003f71f2f3a6bffe3ae3d54a", 16),
    BigInt("581515f2787c8d7d33f41c241b137f78", 16),
    BigInt("34b6c26d50cdb79ae5f89d7ca134789c", 16)
  )


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
    * Test - AESCore_Std (128-bit)
    */
  test("AESCoreStd_128"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new AESCore_Std(128 bits)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for(_ <- 0 to NBR_ITERATION){

        SymmetricCryptoBlockIOSim.doSim(dut.io, dut.clockDomain, enc = Random.nextBoolean() )(AES.block(128, verbose = false))
      }

      // Release the valid signal at the end of the simulation
      dut.io.cmd.valid #= false

      dut.clockDomain.waitActiveEdge()
    }
  }



  /**
    * Test - AESCore_Std (192-bit)
    */
  test("AESCoreStd_192"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new AESCore_Std(192 bits)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()


      for((key, plain, cipher) <- (ref_key_192, ref_plain_192, ref_cipher_192).zipped){

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

      dut.clockDomain.waitActiveEdge()
    }
  }




  /**
    * Test - AESCore_Std (256-bit)
    */
  test("AESCoreStd_256"){

    SimConfig.withConfig(SpinalConfig(inlineRom = true)).compile(new AESCore_Std(256 bits)).doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      SymmetricCryptoBlockIOSim.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      for((key, plain, cipher) <- (ref_key_256, ref_plain_256, ref_cipher_256).zipped){


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

      dut.clockDomain.waitActiveEdge()
    }
  }
}


