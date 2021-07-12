package play

import spinal.core._
import spinal.lib._

import spinal.crypto._
import spinal.crypto.hash._
import spinal.crypto.hash.md5._
import spinal.crypto.mac.hmac.{HMACCoreStdConfig, HMACCoreStdIO, HMACCore_Std}
import spinal.crypto.symmetric.SymmetricCryptoBlockIO
import spinal.crypto.symmetric.des.{DESCore_Std, TripleDESCore_Std}
import spinal.crypto.symmetric.aes._
import spinal.crypto.misc.LFSR



object PlayWithDesCore_Std{

  class DESCoreStdTester extends Component {

    val des = new DESCore_Std()

    val io  = slave(new SymmetricCryptoBlockIO(des.gIO))

    des.io <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new DESCoreStdTester).printPruned
  }
}


object PlayWith3DesCore_Std{

  class TripleDESCoreStdTester extends Component {

    val des3 = new TripleDESCore_Std()

    val io = slave(new SymmetricCryptoBlockIO(des3.gIO))

    des3.io <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new TripleDESCoreStdTester).printPruned
  }
}


object PlayWithMD5Core_Std{

  class MD5CoreStdTester extends Component{

    val md5 = new MD5Core_Std()

    val io = slave(HashCoreIO(md5.configCore))

    md5.io <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new MD5CoreStdTester).printUnused()
  }
}

object PlayWithHMACCore_Std_MD5Core_Std{

  class HMACCoreStdTester() extends Component{

    val md5  = new MD5Core_Std()
    val hmac = new HMACCore_Std(HMACCoreStdConfig(md5.configCore.hashBlockWidth, md5.configCore))

    val io = slave(HMACCoreStdIO(hmac.config))

    hmac.io.hmacCore <> io
    hmac.io.hashCore <> md5.io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz),
      mergeAsyncProcess = false
    ).generate(new HMACCoreStdTester).printPruned
  }
}


object PlayWithAESCore_Std{
  class AESCoreStdTester() extends Component{

    val aes128  = new AESCore_Std(128 bits)
    val aes192  = new AESCore_Std(192 bits)
    val aes256  = new AESCore_Std(256 bits)

    val io = new Bundle{
      val aes_128 = slave(SymmetricCryptoBlockIO(aes128.gIO))
      val aes_192 = slave(SymmetricCryptoBlockIO(aes192.gIO))
      val aes_256 = slave(SymmetricCryptoBlockIO(aes256.gIO))
    }

    aes128.io <> io.aes_128
    aes192.io <> io.aes_192
    aes256.io <> io.aes_256
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = VHDL,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new AESCoreStdTester).printPruned
  }
}


object PlayWithLFSR{

  case class LFSR_CMD() extends Bundle{
    val init  = in Bool()
    val seed  = in Bits(8 bits)
    val inc   = in Bool()
    val value = out Bits(8 bits)
  }

  class LFSRTester() extends Component{

    val io = new Bundle{
      val fib     = LFSR_CMD()
      val gal     = LFSR_CMD()
      val fib_ext = LFSR_CMD()
      val gal_ext = LFSR_CMD()

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

    val fib_ext = new Area {
      val lfsr_reg = Reg(cloneOf(io.fib_ext.value))
      when(io.fib_ext.init){
        lfsr_reg := io.fib_ext.seed
      }
      when(io.fib_ext.inc){
        lfsr_reg := LFSR.Fibonacci(lfsr_reg, LFSR.polynomial_8bits, LFSR.XOR, true)
      }
      io.fib_ext.value := lfsr_reg
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

    val gal_ext = new Area {
      val lfsr_reg = Reg(cloneOf(io.gal_ext.value))
      when(io.gal_ext.init){
        lfsr_reg := io.gal_ext.seed
      }
      when(io.gal_ext.inc){
        lfsr_reg := LFSR.Galois(lfsr_reg, LFSR.polynomial_8bits, LFSR.XOR, true)
      }
      io.gal_ext.value := lfsr_reg
    }

  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new LFSRTester).printPruned
  }
}