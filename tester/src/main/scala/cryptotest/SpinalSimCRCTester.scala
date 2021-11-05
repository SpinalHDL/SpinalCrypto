package cryptotest

import spinal.core._
import spinal.core.sim._
import spinal.crypto.checksum._
import org.scalatest.funsuite.AnyFunSuite
import ref.checksum.crc._
import spinal.crypto.checksum.sim.CRCCombinationalsim

import scala.util.Random


class SpinalSimCRCTester extends AnyFunSuite {


  /**
    * Compute the CRC reference
    */
  def computeCRC(data: List[BigInt], mode: AlgoParams, dataWidth: Int, verbose: Boolean = false): BigInt = {
    val calculator = new CrcCalculator(mode)

    val din = data.map(_.toByteArray.takeRight(dataWidth / 8)).flatten.toArray
    val result = calculator.Calc(din, 0, din.length)

    if (verbose) {
      println(BigInt(result).toString(16))
    }

    return BigInt(result)
  }


  /**
    * Simulate a CRC
    */
  def crcSimulation(crcMode: List[(CRCPolynomial, AlgoParams)], dataWidth: Int){

    for (mode <- crcMode) {

      val config = CRCCombinationalConfig(
        crcConfig = mode._1,
        dataWidth = dataWidth bits
      )

      SimConfig.compile(new CRCCombinational(config)).doSim { dut =>

        val data = List.fill[BigInt](Random.nextInt(10) + 1)(BigInt(dataWidth, Random))

        dut.clockDomain.forkStimulus(2)

        CRCCombinationalsim.doSim(dut.io, dut.clockDomain, data)(computeCRC(data, mode._2, dataWidth))

        dut.clockDomain.waitActiveEdge()
      }
    }
  }


  /**
    * CRC32 with 8-bit data
    */
  test("CRC32_8_combinational"){

    val configurations = List(
      CRC32.Standard  -> Crc32.Crc32,
      CRC32.XFER      -> Crc32.Crc32Xfer
    )

    crcSimulation(configurations, 8)
  }


  /**
    * CRC32 with 16-bit data
    */
  test("CRC32_16_combinational"){

    val configurations = List(
      CRC32.Standard  -> Crc32.Crc32,
      CRC32.XFER      -> Crc32.Crc32Xfer
    )

    crcSimulation(configurations, 16)
  }


  /**
    * CRC32 with 32-bit data
    */
  test("CRC32_32_combinational"){

    val configurations = List(
      CRC32.Standard  -> Crc32.Crc32,
      CRC32.XFER      -> Crc32.Crc32Xfer
    )

    crcSimulation(configurations, 32)
  }


  /**
    * CRC16 with 16-bit data
    */
  test("CRC16_16_combinational"){

    val configurations = List(
      CRC16.XModem      -> Crc16.Crc16Xmodem
    )

    crcSimulation(configurations, 16)
  }


  /**
    * CRC16 with 8-bit data
    */
  test("CRC16_8_combinational"){

    val configurations = List(
      CRC16.XModem   -> Crc16.Crc16Xmodem
    )

    crcSimulation(configurations, 8)
  }


  /**
    * CRC8 with 8-bit data
    */
  test("CRC8_8_combinational") {

    val configurations = List(
      CRC8.Standard      -> Crc8.Crc8,
      CRC8.DARC -> Crc8.Crc8Darc
    )

    crcSimulation(configurations, 8)
  }
}

