package cryptotest

import spinal.core._
import spinal.crypto.symmetric.aes.AESCore_Std
import spinal.lib._

import spinal.crypto.symmetric.des.{DESCore_Std, TripleDESCore_Std}
import spinal.crypto.symmetric._


/**
  * AESCore_Std 128/192/256
  */
class AESCoreStdTester() extends Component{

  val aes128  = new AESCore_Std(128 bits)
  val aes192  = new AESCore_Std(192 bits)
  val aes256  = new AESCore_Std(256 bits)

  val io = new Bundle{
    val aes_128 = slave(SymmetricCryptoBlockIO(aes128.gIO))
    val aes_192 = slave(SymmetricCryptoBlockIO(aes192.gIO))
    val aes_256 = slave(SymmetricCryptoBlockIO(aes256.gIO))
  }

  aes128.io <> io.aes_128
  aes192.io <> io.aes_192
  aes256.io <> io.aes_256
}

/**
  * AESCore_Std 128/192/256
  */
class AESCoreStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "AESCoreStTester"
  override def pythonTestLocation: String = "tester/src/python/crypto/symmetric/AESCore_Std"
  override def createToplevel: Component = new AESCoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}