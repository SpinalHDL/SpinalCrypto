package cryptotest


import spinal.core._
import spinal.lib._
import spinalcrypto.hash.md5._
import spinalcrypto.hash._


/**
  * HMAC core standard tester
  */
class HMACCoreStdTester() extends Component{

  val io = slave(HMACCoreStdIO(HMACCoreStdGeneric()))

  val hmac = new HMACCore_Std()
  val md5  = new MD5Core_Std()

  hmac.io.hmacCore <> io
  hmac.io.hashCore <> md5.io
}

class HMACCoreStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "HMACCoreStdTester"
  override def pythonTestLocation: String = "src/test/python/crypto/hash/HMACCore_Std"
  override def createToplevel: Component = new HMACCoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}
