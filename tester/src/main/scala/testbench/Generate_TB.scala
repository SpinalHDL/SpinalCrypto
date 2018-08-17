package testbench

import spinal.core._
import spinal.crypto.checksum._
import spinal.lib._
import spinal.lib.bus.amba4.axi.{Axi4, Axi4SpecRenamer, Axi4ToAxi4Shared}
import spinal.lib.com.uart.Uart


case class AxiCryptoTB_Config(
                               enableUART : Boolean,
                               enableGPIO : Boolean,
                               nbrGPIO    : Int
                             )

object Generate_TB extends App {

  // Configuration
  val enableUART = false
  val enableGPIO = false
  val nbrGPIO    = 2


  val listAlgo = List(
    () => new Apb3_DESCore_Std(),
    () => new Apb3_3DESCore_Std(),
    () => new Apb3_AESCore_Std(128 bits),
    () => new Apb3_AESCore_Std(192 bits),
    () => new Apb3_AESCore_Std(256 bits),
    () => new Apb3_MD5Core_Std(),
    () => new Apb3_HMAC_Std_MD5Core_Std(),
    () => new Apb3_CRC_Combinational(CRCCombinationalConfig(CRC32.Standard, dataWidth = 32 bits))
  )

  val spinalConfig = SpinalConfig(
    mode = VHDL,
    defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
    defaultClockDomainFrequency  = FixedFrequency(50 MHz)
  )

  spinalConfig.generate(new SocCryptoVexRiscv(CryptoCPUConfig.de1_soc.copy(enableUart = enableUART, enableGPIO = enableGPIO, nbrGPIO = nbrGPIO))(listAlgo: _*))
  spinalConfig.generate(new AxiCrypto_TB(AxiCryptoTB_Config(enableUART = enableUART, enableGPIO = enableGPIO, nbrGPIO = nbrGPIO))(listAlgo: _*))
}



class AxiCrypto_TB(config: AxiCryptoTB_Config)(apbSlaves: (() => ApbCryptoComponent)*) extends Component {

  val cryptoCore =  new AxiShared2Apb_TB(AxiShared2Apb_TB.defaultConfig.copy(enableUART = config.enableGPIO, enableGPIO = config.enableGPIO, nbrGPIO = config.nbrGPIO))(apbSlaves: _*)

  val io = new Bundle{
    val axi    = slave(Axi4(cryptoCore.config.axiConfig))
    val gpioA  = if(config.enableGPIO) out Bits(config.nbrGPIO bits) else null
    val uart   = if(config.enableUART) master(Uart()) else null
  }

  Axi4SpecRenamer(io.axi)

  cryptoCore.io.axiShared << Axi4ToAxi4Shared(io.axi)

  if(config.enableGPIO){
    io.gpioA := cryptoCore.io.gpioA.write
    cryptoCore.io.gpioA.read := 0
  }

  if(config.enableUART) io.uart <> cryptoCore.io.uart
}
