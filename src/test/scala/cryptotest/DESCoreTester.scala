package cryptotest

import spinal.core._
import spinal.lib._

import spinal.crypto.symmetric.des.{TripleDESCore_Std}
import spinal.crypto.symmetric._


/**
  * Triple DES component
  */
class TripleDESCoreStdTester extends Component {

  val des3 = new TripleDESCore_Std()

  val io = slave(new SymmetricCryptoBlockIO(des3.gIO))

  des3.io <> io
}

/**
  * Triple DES cocotb Test
  */
class TripleDESCoreStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "TripleDESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/TripleDESCore_Std"
  override def createToplevel: Component = new TripleDESCoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}