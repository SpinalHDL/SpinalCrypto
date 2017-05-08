package cryptotest

import spinal.core._
import spinal.lib._
import spinalcrypto.hash.md5._

/**
  * MD5 Engine standard tester
  */
class MD5EngineStdTester extends Component{

  val io = slave(MD5EngineStdIO())

  val md5 = new MD5Engine_Std()
  md5.io <> io
}

class MD5EngineStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "MD5EngineStdTester"
  override def pythonTestLocation: String = "src/test/python/crypto/hash/MD5Engine_Std"
  override def createToplevel: Component = new MD5EngineStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}


/**
  * MD5 Core standard tester
  */
class MD5CoreStdTester extends Component{

  val md5 = new MD5Core_Std()

  val io = slave(MD5CoreStdIO(md5.g))


  md5.io <> io
}

class MD5CoreStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "MD5CoreStdTester"
  override def pythonTestLocation: String = "src/test/python/crypto/hash/MD5Core_Std"
  override def createToplevel: Component = new MD5CoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}

