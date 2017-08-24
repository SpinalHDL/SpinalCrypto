package spinal.crypto.misc


import spinal.crypto.misc.CRC.BitOrder
import scala.collection.mutable.ListBuffer

import spinal.core._
import spinal.lib._


object CRC{

  trait CRC_POLYNOMIAL{ def polynomial : String}
  case object CRC_32 extends CRC_POLYNOMIAL{ def polynomial = "100000100110000010001110110110111" } // x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x^1+1
  case object CRC_16 extends CRC_POLYNOMIAL{ def polynomial = "11000000000000101" } // x^16+x^15+x^2+1
  case object CRC_8  extends CRC_POLYNOMIAL{ def polynomial = "100000111" }  //x^8 + x^2 + x^1 + 1

  trait BitOrder { def lsb : Boolean }
  case object LSB extends BitOrder { def lsb = true }
  case object MSB extends BitOrder { def lsb = false }
}


//TODO Add init value of the crc register ....
// TODO add MSB or LSB first data
// TODO some doc ... http://www.sigmatone.com/utilities/crc_generator/crc_generator.htm
/**
  * Generic
  *
  * @param crcPolynomial : String representing the equation
  * @param dataWidth     : Bus data width
  * @param initVector    : Init crc value
  * @param firstBit      : First serial bit LSB or MSB
  */
case class CRCCombinationalGeneric (crcPolynomial : String,
                                    dataWidth     : BitCount,
                                    initVector    : Bits,
                                    firstBit      : BitOrder = CRC.LSB
                                   ){

  val crcWidth = (crcPolynomial.size - 1) bits
}


object CRCCombinationalCmdMode extends SpinalEnum{
  val INIT, UPDATE = newElement()
}


case class CRCCombinationalCmd(g:CRCCombinationalGeneric) extends Bundle{
  val mode = CRCCombinationalCmdMode()
  val data = Bits(g.dataWidth)
}


class CRCCombinational(g:CRCCombinationalGeneric) extends Component{

  import spinal.crypto.misc.{CRCCombinationalCmdMode => CmdMode}

  val io = new Bundle{
    val cmd = slave  Flow(CRCCombinationalCmd(g))
    val rsp = master Flow(Bits(g.dataWidth))
  }

  val crcReg   = Reg(Bits(g.crcWidth))
  val rspValid = False

  when(io.cmd.valid && io.cmd.mode === CmdMode.INIT){
    crcReg.setAll() // := B(0, g.crcWidth) //  g.initVector
  }

  when(io.cmd.valid && io.cmd.mode === CmdMode.UPDATE){
    crcReg   := CRCCombinationalCore(io.cmd.data, crcReg, g.crcPolynomial, g.crcWidth.value)
    rspValid := True
  }

  io.rsp.valid   := rspValid
  io.rsp.payload := ~Reverse(crcReg)
}


/**
  * CRC combinational core
  */
object CRCCombinationalCore {

  def apply(data:Bits, crc:Bits, polynomial:String, dataWidth:Int ) : Bits ={

    val newCRC = cloneOf(crc)
    val dataR  = EndiannessSwap(data)

    val listXor = lfsrCRCGenerator(polynomial, data.getWidth)

    for(i <- 0 until data.getWidth){
      newCRC(i) := listXor(i).map(t => if (t._1 == "D") dataR(t._2) else crc(t._2)).reduce(_ ^ _)
    }

    newCRC
  }

  /**
    * Use a LFSR to compute the xor combination for each index in order to perform the CRC in one clock
    *
    * Rule : Build a LFSR from a polynomial :
    *                1 * x^0 = 1 => feedback
    *                1 * x^n     => x^n xor x^(n-1)
    *                0 * x^0     => do noting
    *
    * e.g : x^3+x+1
    *
    *          /-------------------------------------------XOR<-- D0,D1,D2
    *          |   ____     |      ____              ____   |
    *          \->|_C0_|---XOR--->|_C1_|------------|_C2_|--/
    *      0:       c0              c1                c2         D0,D1,D2
    *      1:      c2^d0         c0^c2^d0             c1         D1,D2
    *      2:      c1^d1        c2^d0^c1^d1        c0^c2^d0      D2
    *      3:   c0^c2^d0^d2   c1^d1^c0^c2^d0^d2   c2^d0^c1^d1    -
    *
    *      crc(0) = c0^c2^d0^d2
    *      crc(1) = c1^d1^c0^c2^d0^d2
    *      crc(2) = c2^d0^c1^d1
    */
  // TODo put thisi function as private
  def lfsrCRCGenerator(polynomial:String, dataWidth:Int):List[List[(String,Int)]]={

    assert(dataWidth < polynomial.size, "dataWidth can't be bigger than the polynomial length")

    val listPolynomial = polynomial.toList

    val lenLFSR = polynomial.size - 1 // nbr of register used by the LFSR

    // initialize the lfsr register
    var lfsr = (for(i <- 0 until lenLFSR) yield List("C"+i)).toList

    // execute the LFSR dataWidth number of time
    for(j <- 0 until dataWidth) {
      val result = new ListBuffer[List[String]]()
      for (i <- 0 until lenLFSR) {
        if (i == 0) {
          result += lfsr(lenLFSR-1) ::: List("D" + j)
        } else if (listPolynomial(lenLFSR - i) == '0') {
          result += lfsr(i - 1)
        } else {
          result += lfsr(i - 1) ::: lfsr(lenLFSR - 1) ::: List("D" + j)
        }
      }
      lfsr = result.toList
    }

    // Simplify (odd number => replace by one occurence, even number => remove all occurence)
    val finalRes = new ListBuffer[List[(String,Int)]]()
    for(lt <- lfsr){
      val listD = (for(i <- 0 until lenLFSR if (lt.count(_ == "D" + i ) % 2  == 1)) yield ("D",i)).toList
      val listC = (for(i <- 0 until lenLFSR if (lt.count(_ == "C" + i ) % 2  == 1)) yield ("C",i)).toList
      finalRes += (listD ++ listC)
    }

    println("--------")
    //println(finalRes)
    finalRes.foreach(println(_))
    println("--------")

    finalRes.toList
  }
}


object FakeCRCTest{
  def main(args: Array[String]) {
    val polynomila = CRC.CRC_8.polynomial
    CRCCombinationalCore.lfsrCRCGenerator(polynomila, 8)
  }
}