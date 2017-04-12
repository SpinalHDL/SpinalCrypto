package cryptotest

import spinal.core._
import spinalcrypto.symmetric._



/**
  * DESBlock component
  */
class DESBlockTester extends Component {

  val des = new DESBlock()

  val io  = new SymmetricCryptoBlockIO(des.gIO)

  des.io <> io
}


/**
  * DES Block cocotb Test
  */
class DESBlockCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "DESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/DESBlock"
  override def createToplevel: Component = new DESBlockTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}



/**
  * Triple DES component
  */
class TripleDESBlockTester extends Component {

  val des3 = new TripleDESBlock()

  val io = new SymmetricCryptoBlockIO(des3.gIO)

  des3.io <> io
}

/**
  * Triple DES cocotb Test
  */
class TripleDESBlockCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "TripleDESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/TripleDESBlock"
  override def createToplevel: Component = new TripleDESBlockTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}