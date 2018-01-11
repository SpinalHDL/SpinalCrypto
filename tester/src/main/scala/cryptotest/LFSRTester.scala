package cryptotest

import spinal.core._
import spinal.crypto.misc.LFSR




/**
  * LFSR Fibonacci and Galois
  */
class LFSRTester() extends Component{

  case class LFSR_CMD() extends Bundle{
    val init  = in Bool
    val seed  = in Bits(8 bits)
    val inc   = in Bool
    val value = out Bits(8 bits)
  }

  val io = new Bundle {
    val fib = LFSR_CMD()
    val gal = LFSR_CMD()
    val fib_ext = LFSR_CMD()
    val gal_ext = LFSR_CMD()

  }

  val fib = new Area {
    val lfsr_reg = Reg(cloneOf(io.fib.value))
    when(io.fib.init) {
      lfsr_reg := io.fib.seed
    }
    when(io.fib.inc) {
      lfsr_reg := LFSR.Fibonacci(lfsr_reg, LFSR.polynomial_8bits)
    }
    io.fib.value := lfsr_reg
  }

  val fib_ext = new Area {
    val lfsr_reg = Reg(cloneOf(io.fib_ext.value))
    when(io.fib_ext.init) {
      lfsr_reg := io.fib_ext.seed
    }
    when(io.fib_ext.inc) {
      lfsr_reg := LFSR.Fibonacci(lfsr_reg, LFSR.polynomial_8bits, LFSR.XOR, true)
    }
    io.fib_ext.value := lfsr_reg
  }

  val gal = new Area {
    val lfsr_reg = Reg(cloneOf(io.gal.value))
    when(io.gal.init) {
      lfsr_reg := io.gal.seed
    }
    when(io.gal.inc) {
      lfsr_reg := LFSR.Galois(lfsr_reg, LFSR.polynomial_8bits)
    }
    io.gal.value := lfsr_reg
  }

  val gal_ext = new Area {
    val lfsr_reg = Reg(cloneOf(io.gal_ext.value))
    when(io.gal_ext.init) {
      lfsr_reg := io.gal_ext.seed
    }
    when(io.gal_ext.inc) {
      lfsr_reg := LFSR.Galois(lfsr_reg, LFSR.polynomial_8bits, LFSR.XOR, true)
    }
    io.gal_ext.value := lfsr_reg
  }
}

/**
  * LFSR Fibonacci and Galois
  */
class LFSRTesterCocotbBoot extends SpinalTesterCocotbBase {

  override def getName: String = "LFSRTester"
  override def pythonTestLocation: String = "tester/src/python/crypto/misc/lfsr"
  override def createToplevel: Component = new LFSRTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}