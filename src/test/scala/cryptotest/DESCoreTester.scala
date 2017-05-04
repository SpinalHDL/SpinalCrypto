package cryptotest

import spinal.core._
import spinal.lib._
import spinalcrypto.symmetric.des.{DESCore_Std, TripleDESCore_Std}
import spinalcrypto.symmetric._



/**
  * DESBlock component
  */
class DESCoreStdTester extends Component {

  val des = new DESCore_Std()

  val io  = slave(new SymmetricCryptoCoreIO(des.gIO))

  des.io <> io
}


/**
  * DES Block cocotb Test
  */
class DESCoreStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "DESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/DESCore_Std"
  override def createToplevel: Component = new DESCoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}



/**
  * Triple DES component
  */
class TripleDESCoreStdTester extends Component {

  val des3 = new TripleDESCore_Std()

  val io = slave(new SymmetricCryptoCoreIO(des3.gIO))

  des3.io <> io
}

/**
  * Triple DES cocotb Test
  */
class TripleDESCoreCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "TripleDESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/TripleDESCore_Std"
  override def createToplevel: Component = new TripleDESCoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}