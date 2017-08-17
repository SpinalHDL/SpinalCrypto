package cryptotest


import spinal.core._
import spinal.lib._

import spinal.crypto.hash.md5._
import spinal.crypto.hmac.{HMACCoreStdGeneric, HMACCoreStdIO, HMACCore_Std}


/**
  * HMAC core standard tester
  */
class HMACCoreStdTester() extends Component{

  val md5  = new MD5Core_Std()
  val hmac = new HMACCore_Std(HMACCoreStdGeneric(md5.g.hashBlockWidth, md5.g))

  val io = slave(HMACCoreStdIO(hmac.g))

  hmac.io.hmacCore <> io
  hmac.io.hashCore <> md5.io
}

class HMACCoreStdCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "HMACCoreStdTester"
  override def pythonTestLocation: String = "src/test/python/crypto/mac/HMACCore_Std"
  override def createToplevel: Component = new HMACCoreStdTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}
