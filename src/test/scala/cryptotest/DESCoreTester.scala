package cryptotest

import spinal.core._
import spinalcrypto.symmetric._



/**
  * DESBlock component
  */
class DESCoreTester extends Component {

  val des = new DESCore()

  val io  = new SymmetricCryptoBlockIO(des.gIO)

  des.io <> io
}


/**
  * DES Block cocotb Test
  */
class DESCoreCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "DESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/DESCore"
  override def createToplevel: Component = new DESCoreTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}



/**
  * Triple DES component
  */
class TripleDESCoreTester extends Component {

  val des3 = new TripleDESCore()

  val io = new SymmetricCryptoBlockIO(des3.gIO)

  des3.io <> io
}

/**
  * Triple DES cocotb Test
  */
class TripleDESCoreCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "TripleDESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/TripleDESCore"
  override def createToplevel: Component = new TripleDESCoreTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}