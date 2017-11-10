package cryptotest

import spinal.core._
import spinal.crypto.misc.LFSR


/**
  * LFSR Fibonacci and Galois
  */
class LFSRTester() extends Component{

  val io = new Bundle{
    val fib = new Bundle{
      val init  = in Bool
      val seed  = in Bits(8 bits)
      val inc   = in Bool
      val value = out Bits(8 bits)
    }
    val gal = new Bundle{
      val init  = in Bool
      val seed  = in Bits(8 bits)
      val inc   = in Bool
      val value = out Bits(8 bits)
    }
  }

  val fib = new Area {
    val lfsr_reg = Reg(cloneOf(io.fib.value))
    when(io.fib.init){
      lfsr_reg := io.fib.seed
    }
    when(io.fib.inc){
      lfsr_reg := LFSR.Fibonacci(lfsr_reg, LFSR.polynomial_8bits)
    }
    io.fib.value := lfsr_reg
  }

  val gal = new Area {
    val lfsr_reg = Reg(cloneOf(io.gal.value))
    when(io.gal.init){
      lfsr_reg := io.gal.seed
    }
    when(io.gal.inc){
      lfsr_reg := LFSR.Galois(lfsr_reg, LFSR.polynomial_8bits)
    }
    io.gal.value := lfsr_reg
  }
}

/**
  * LFSR Fibonacci and Galois
  */
class LFSRTesterCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "LFSRTester"
  override def pythonTestLocation: String = "src/test/python/crypto/misc/lfsr/LFSR_Tester"
  override def createToplevel: Component = new LFSRTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}