package cryptotest

import spinal.core._
import spinalcrypto.hash._
import spinal.lib._
import spinalcrypto.hash.md5.{MD5Core, MD5CoreCmd, MD5CoreRsp}

/**
  * MD5 core tester
  */
class MD5CoreTester extends Component{
  val io = new Bundle{
    val init = in Bool
    val cmd  = slave Stream(MD5CoreCmd())
    val rsp  = master Flow(MD5CoreRsp())
  }

  val md5 = new MD5Core()
  md5.io <> io
}

/**
  * MD5 cocotb Test
  */
class MD5CoreCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "MD5CoreTester"
  override def pythonTestLocation: String = "src/test/python/crypto/hash/MD5Core"
  override def createToplevel: Component = new TripleDESCoreTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}