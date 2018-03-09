package testbench

import spinal.core._
import spinal.crypto.checksum._
import spinal.lib._
import spinal.lib.bus.amba4.axi.{Axi4, Axi4ToAxi4Shared}
import spinal.lib.com.uart.Uart


object Generate_TB extends App {

  val enableUART = true

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


  spinalConfig.generate(new SocCryptoVexRiscv(CryptoCPUConfig.de1_soc.copy(enableUart = enableUART))(listAlgo: _*))
  spinalConfig.generate(new AxiCrypto_TB(enableUART)(listAlgo: _*))
}



class AxiCrypto_TB(enableUART: Boolean)(apbSlaves: (() => ApbCryptoComponent)*) extends Component {

  val cryptoCore =  new AxiShared2Apb_TB(AxiShared2Apb_TB.defaultConfig.copy(addUartSlave = enableUART))(apbSlaves: _*)

  val io = new Bundle{
    val axi    = slave(Axi4(cryptoCore.config.axiConfig))
    val gpioA  = out Bits(32 bits)
    val uart   = if(enableUART) master(Uart()) else null
  }

  cryptoCore.io.axiShared << Axi4ToAxi4Shared(io.axi)
  io.gpioA := cryptoCore.io.gpioA.write
  cryptoCore.io.gpioA.read := 0
  if(enableUART) io.uart <> cryptoCore.io.uart
}
