package spinalcrypto.hash

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._

import scala.math.{pow, sin}

import scala.collection.mutable.ListBuffer

case class MD5CoreCmd() extends Bundle{
  val block = Bits(MD5CoreSpec.msgBlockSize)
}

case class MD5CoreRsp() extends Bundle{
  val digest = Bits(MD5CoreSpec.digestBlockSize)
}

object MD5CoreSpec{

  def msgBlockSize    = 512 bits
  def subBlockSize    = 32 bits
  def digestBlockSize = 128 bits
  def nbrIteration    = 64

  def initBlockA = B"x67452301"
  def initBlockB = B"xEFCDAB89"
  def initBlockC = B"x98BADCFE"
  def initBlockD = B"x10325476"

  def funcF(b: Bits, c: Bits, d: Bits): Bits = (b & c) | (~b & d)
  def funcG(b: Bits, c: Bits, d: Bits): Bits = (b & d) | (~d & c)
  def funcH(b: Bits, c: Bits, d: Bits): Bits = b ^ c ^ d
  def funcI(b: Bits, c: Bits, d: Bits): Bits = c ^ (b | ~d)


  /**
    * K[i] := floor(2^32 × abs(sin(i + 1)))
    */
  def constantK: List[BigInt] = for(i <- List.range(0,64)) yield BigDecimal((pow(2,32) * sin(i + 1.0).abs)).toBigInt()


  def shiftValue: List[Int] = List(7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                                   5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                                   4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                                   6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21)

  /**
    *  0 .. 15 : index = i
    * 16 .. 31 : index = 5 * i + 1 mod 16
    * 32 .. 47 : index = 3 * i + 5 mod 16
    * 63 .. 34 : index = 7 * i mod 16
    */
  def indexG: List[Int] = {
    val res = new ListBuffer[Int]()

    for(i <- 0 until 64){
      if(i < 16){
        res.append(i)
      }else if(i < 32){
        res.append((5 * i + 1) % 16)
      }else if(i < 48){
        res.append((3 * i + 5) % 16)
      }else{
        res.append((7 * i) % 16)
      }
    }

    res.toList
  }
}

/**
  * The MD5 algorithm is a hash function producing a 128-bit hash value. MD5 works with block of 512-bit. The message to
  * hash must be padded as following:
  *    - Add a one bit a the end of the message
  *    - Add a sequence of 0 until to get a block of 448-bits
  *    - Write the size of the message on 64 bits
  *
  * doc : https://www.ietf.org/rfc/rfc1321.txt
  *
  */
class MD5Core extends Component{

  val io = new Bundle{
    val init = in Bool
    val cmd  = slave Stream(MD5CoreCmd())
    val rsp  = master Flow(MD5CoreRsp())
  }


  val msgBlock = B(0, MD5CoreSpec.msgBlockSize)

  val blockA   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val blockB   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val blockC   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val blockD   = Reg(Bits(MD5CoreSpec.subBlockSize))


  val memT     = Mem(UInt(32 bits), MD5CoreSpec.constantK.map(U(_, 32 bits)))
  val memShift = Mem(UInt(5 bits),  MD5CoreSpec.shiftValue.map(U(_, 5 bits)))
  val memIndex = Mem(UInt(4 bits),  MD5CoreSpec.indexG.map(U(_, 4 bits)))



  /**
    * Iteractive round:
    * X : message block
    * T : constant table
    *         _______ _______ _______ _______
    *        |   A   |   B   |   C   |   D   |
    *         ------- ------- ------- -------
    *             |     |  \____   |   ___|
    *             |     |      _\__|__/_
    *             + ----------|   Func  |
    *             |     |      ---------
    *    X[k] --> +     |
    *             |     |
    *    T[i] --> +     |
    *             |     |
    *            << S   |
    *             |     |
    *             + <---/
    *             |
    *             \______
    *                    \
    *            D       |       B       C
    *         ___|___ ___|___ ___|___ ___|___
    *        |   A'  |   B'  |   C'  |   D'  |
    *         ------- ------- ------- -------
    */
  val iteractiveCore = new Area{

    val selFunc = Bits(2 bits)

    val k = Reg(UInt(4 bits))
    val i = Reg(UInt(6 bits))

    k := memIndex(i)

    val funcResult = selFunc.mux(B"00" -> MD5CoreSpec.funcF(blockB, blockC, blockD),
                                 B"01" -> MD5CoreSpec.funcG(blockB, blockC, blockD),
                                 B"10" -> MD5CoreSpec.funcH(blockB, blockC, blockD),
                                 B"11" -> MD5CoreSpec.funcI(blockB, blockC, blockD))

    val add1      = funcResult.asUInt + blockA.asUInt
    val wordBlock = k.muxList(for(i <- 0 until 16) yield (i, msgBlock(i*32+32-1 downto i*32)))
    val msgAdd    = wordBlock.asUInt + add1
    val tAdd      = msgAdd + memT(i)
    val shiftAdd  = tAdd.rotateLeft(memShift(i))

    blockA := blockD
    blockB := shiftAdd.asBits
    blockC := blockB
    blockD := blockC
  }


  val lastStep = new Area{
    when(iteractiveCore.i === 63){
      blockA := (blockA.asUInt + MD5CoreSpec.initBlockA.asUInt).asBits
      blockB := (blockB.asUInt + MD5CoreSpec.initBlockB.asUInt).asBits
      blockC := (blockC.asUInt + MD5CoreSpec.initBlockC.asUInt).asBits
      blockD := (blockD.asUInt + MD5CoreSpec.initBlockD.asUInt).asBits
    }
  }


  val smMD5 = new StateMachine{

    val isOver = False
    iteractiveCore.selFunc := 0

    val sIdle: State = new State with EntryPoint {
      whenIsActive{
        when(io.init){
          blockA := MD5CoreSpec.initBlockA
          blockB := MD5CoreSpec.initBlockB
          blockC := MD5CoreSpec.initBlockC
          blockD := MD5CoreSpec.initBlockD
          iteractiveCore.i := 0
          iteractiveCore.k := 0
          iteractiveCore.selFunc := 0
          goto(sStart)
        }
      }
    }
    val sStart: State = new State{
      whenIsActive{
        when(io.cmd.valid){
          msgBlock := io.cmd.block
          goto(sProcessing)
        }
      }
    }

    val sProcessing: State = new State{
      whenIsActive{

        iteractiveCore.i := iteractiveCore.i + 1

        when(iteractiveCore.i < 16){
          iteractiveCore.selFunc := 0
        }.elsewhen(iteractiveCore.i < 32){
          iteractiveCore.selFunc := 1
        }.elsewhen(iteractiveCore.i < 45){
          iteractiveCore.selFunc := 2
        }.otherwise{
          iteractiveCore.selFunc := 3
        }

        when(iteractiveCore.i === 63){
          isOver := True
          goto(sIdle)
        }
      }
    }
  }

  io.rsp.digest := blockD ## blockC ## blockB ## blockA
  io.rsp.valid  := smMD5.isOver
  io.cmd.ready  := smMD5.isOver
}


object PlayWithMD5{

  class MD5CoreTester extends Component{
    val io = new Bundle{
      val init = in Bool
      val cmd  = slave Stream(MD5CoreCmd())
      val rsp  = master Flow(MD5CoreRsp())
    }

    val md5 = new MD5Core()
    md5.io <> io
  }

  def main(args: Array[String]): Unit = {


    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new MD5CoreTester).printPruned()
  }
}