package cryptotest


import org.scalatest.funsuite.AnyFunSuite
import spinal.core._
import spinal.core.sim._
import spinal.crypto.misc.LFSR

import scala.collection.mutable.ListBuffer


case class LFSR_IO_TEST() extends Bundle{
  val init  = in Bool()
  val seed  = in Bits(8 bits)
  val inc   = in Bool()
  val value = out Bits(8 bits)
}

object LFSR_IO_SIM{

  def initializeIO(dut: LFSR_IO_TEST): Unit ={
    dut.init #= false
    dut.seed.randomize()
    dut.inc  #= false
  }

  def doSim(dut: LFSR_IO_TEST, clockDomain: ClockDomain, order_poly: Int,  extended: Boolean): Unit = {

    val lfsr_buf = new ListBuffer[BigInt]()

    // init
    dut.init #= true
    dut.seed #= 1

    clockDomain.waitActiveEdge()
    dut.init #= false

    clockDomain.waitActiveEdge()
    dut.inc #= true

    // iteration
    val iteration = if(extended) math.pow(2, order_poly).toInt else math.pow(2, order_poly).toInt - 1

    for(_ <- 0 until iteration){
      clockDomain.waitActiveEdge()

      val value = dut.value.toBigInt

      assert(!lfsr_buf.contains(value), s"Duplicate value found ${lfsr_buf.length} -> ${lfsr_buf}")

      lfsr_buf.append(value)
    }


    assert(lfsr_buf.length == iteration , "Not enough or too many number generated")
  }
}


/**
  * LFSR Fibonacci and Galois
  */
class LFSRTester(lfsr: (Bits) => (Bits)) extends Component {

  val io = LFSR_IO_TEST()

  val lfsr_reg = Reg(cloneOf(io.value))

  when(io.init) {
    lfsr_reg := io.seed
  }

  when(io.inc) {
    lfsr_reg := lfsr(lfsr_reg)
  }

  io.value := lfsr_reg
}



class SpinalSimLFSRTester extends AnyFunSuite {

  // RTL to simulate
  val compiledRTL_galois      = SimConfig.compile(new LFSRTester((reg: Bits) => LFSR.Galois(reg, LFSR.polynomial_8bits)))
  val compiledRTL_galois_ext  = SimConfig.compile(new LFSRTester((reg: Bits) => LFSR.Galois(reg, LFSR.polynomial_8bits, LFSR.XOR, true)))
  val compiledRTL_galois_xnor = SimConfig.compile(new LFSRTester((reg: Bits) => LFSR.Galois(reg, LFSR.polynomial_8bits, LFSR.XNOR, false)))

  val compiledRTL_fibonacci     = SimConfig.compile(new LFSRTester((reg: Bits) => LFSR.Fibonacci(reg, LFSR.polynomial_8bits)))
  val compiledRTL_fibonacci_ext = SimConfig.compile(new LFSRTester((reg: Bits) => LFSR.Fibonacci(reg, LFSR.polynomial_8bits, LFSR.XOR, true)))


  /**
    * Test - Galois
    */
  test("LFSR_Galois"){

    compiledRTL_galois.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      LFSR_IO_SIM.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      LFSR_IO_SIM.doSim(dut.io, dut.clockDomain, order_poly = 8, extended = false)

    }
  }


  /**
    * Test - Galois
    */
  test("LFSR_Galois_ext"){

    compiledRTL_galois_ext.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      LFSR_IO_SIM.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      LFSR_IO_SIM.doSim(dut.io, dut.clockDomain, order_poly = 8, extended = true)

    }
  }

  /**
    * Test - Galois
    */
  test("LFSR_Galois_xnor"){

    compiledRTL_galois_xnor.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      LFSR_IO_SIM.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      LFSR_IO_SIM.doSim(dut.io, dut.clockDomain, order_poly = 8, extended = false)

    }
  }


  /**
    * Test - Fibonacci
    */
  test("LFSR_fibonacci"){

    compiledRTL_fibonacci.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      LFSR_IO_SIM.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      LFSR_IO_SIM.doSim(dut.io, dut.clockDomain, order_poly = 8, extended = false)

    }
  }


  /**
    * Test - Fibonacci
    */
  test("LFSR_fibonacci_ext"){

    compiledRTL_fibonacci_ext.doSim{ dut =>

      dut.clockDomain.forkStimulus(2)

      // initialize value
      LFSR_IO_SIM.initializeIO(dut.io)

      dut.clockDomain.waitActiveEdge()

      LFSR_IO_SIM.doSim(dut.io, dut.clockDomain, order_poly = 8, extended = true)

    }
  }
}
