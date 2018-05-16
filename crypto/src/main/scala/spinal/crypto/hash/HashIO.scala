/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/  MIT Licence                      **
**                                                                           **
** Permission is hereby granted, free of charge, to any person obtaining a   **
** copy of this software and associated documentation files (the "Software"),**
** to deal in the Software without restriction, including without limitation **
** the rights to use, copy, modify, merge, publish, distribute, sublicense,  **
** and/or sell copies of the Software, and to permit persons to whom the     **
** Software is furnished to do so, subject to the following conditions:      **
**                                                                           **
** The above copyright notice and this permission notice shall be included   **
** in all copies or substantial portions of the Software.                    **
**                                                                           **
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS   **
** OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                **
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.    **
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY      **
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT **
** OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR  **
** THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                **
\*                                                                           */
package spinal.crypto.hash

import spinal.core._
import spinal.lib._
import spinal.lib.bus.misc.BusSlaveFactory
import spinal.lib.fsm._

trait EndiannessMode
object BIG_endian    extends EndiannessMode
object LITTLE_endian extends EndiannessMode

/**
  * Hash Core configuration
  */
case class HashCoreConfig (
  dataWidth      : BitCount,
  hashWidth      : BitCount,
  hashBlockWidth : BitCount
)


/**
  * Configuration of the Hash Padding core
  */
case class HashPaddingConfig(
  endianess  : EndiannessMode
)


/**
  * Hash Core command
  */
case class HashCoreCmd(config: HashCoreConfig) extends Bundle {
  val msg  = Bits(config.dataWidth)
  val size = UInt(log2Up(config.dataWidth.value / 8) bits)
}


/**
  * Hash Core response
  */
case class HashCoreRsp(config: HashCoreConfig) extends Bundle {
  val digest = Bits(config.hashWidth)
}


/**
  * Hash Core IO
  */
case class HashCoreIO(config: HashCoreConfig) extends Bundle with IMasterSlave {

  val init = in Bool
  val cmd  = Stream(Fragment(HashCoreCmd(config)))
  val rsp  = Flow(HashCoreRsp(config))

  override def asMaster() = {
    out(init)
    master(cmd)
    slave(rsp)
  }

  /** Drive IO from a bus */
  def driveFrom(busCtrl: BusSlaveFactory, baseAddress: Int = 0) = new Area {

    var addr = baseAddress

    /* Write operation */

    busCtrl.driveMultiWord(cmd.msg,   addr)
    addr += (widthOf(cmd.msg) / 32) * 4

    busCtrl.drive(cmd.size, addr)
    addr += 4

    busCtrl.drive(cmd.last, addr)
    addr += 4

    val initReg = busCtrl.drive(init, addr) init(False)
    initReg.clearWhen(initReg)
    addr += 4

    val validReg = busCtrl.drive(cmd.valid, addr) init(False)
    validReg.clearWhen(cmd.ready)
    addr += 4

    /* Read operation */

    val digest   = Reg(cloneOf(rsp.digest))
    val rspValid = Reg(Bool) init(False) setWhen(rsp.valid)

    when(rsp.valid){
      digest := rsp.digest
    }

    busCtrl.onRead(addr){
      when(rspValid){
        rspValid := False
      }
    }

    busCtrl.read(rspValid, addr)
    addr += 4

    busCtrl.readMultiWord(digest, addr)
    addr += (widthOf(digest) / 32) * 4


    //manage interrupts
    val interruptCtrl = new Area {
      val doneIntEnable = busCtrl.createReadAndWrite(Bool, address = addr, 0) init(False)
      val doneInt       = doneIntEnable & !rsp.valid
      val interrupt     = doneInt
    }
  }
}


/**
  * Hash Engine command
  */
case class HashEngineCmd(blockSize: BitCount) extends Bundle {
  val message = Bits(blockSize)
}


/**
  * Hash Engine response
  */
case class HashEngineRsp(digestSize: BitCount) extends Bundle {
  val digest = Bits(digestSize)
}


/**
  * Hash Engine IO
  */
case class HashEngineIO(blockSize: BitCount, digestSize: BitCount) extends Bundle with IMasterSlave {

  val init = Bool
  val cmd  = Stream(HashEngineCmd(blockSize))
  val rsp  = Flow(HashEngineRsp(digestSize))

  override def asMaster() = {
    out(init)
    master(cmd)
    slave(rsp)
  }
}


/**
  * Hash Padding
  *
  * The message to hash must be padded as following:
  *    - Add a one bit a the end of the message
  *    - Add a sequence of 0 until to get a block of 448-bits
  *    - Write the size in bits of the message on 64 bits (l0 l1) e.g : 24 bits => 00000018 00000000
  *
  */
class HashPadding_Std(configCore: HashCoreConfig, configPadding: HashPaddingConfig) extends Component {

  assert(configCore.dataWidth.value == 32, "Currently Hash padding supports only 32 bits")

  val io = new Bundle{
    val core    = slave(HashCoreIO(configCore))
    val engine  = master(HashEngineIO(configCore.hashBlockWidth , configCore.hashWidth))
  }

  val nbrWordInBlock = configCore.hashBlockWidth.value / configCore.dataWidth.value
  val nbrByteInWord  = configCore.dataWidth.value / 8

  val cntBit     = Reg(UInt(64 bits))
  val block      = Reg(Vec(Bits(configCore.dataWidth), nbrWordInBlock))
  val indexWord  = Reg(UInt(log2Up(nbrWordInBlock) bits))


  val maskMsg = io.core.cmd.size.mux(
    U"00"  -> (if(configPadding.endianess == LITTLE_endian) B"x000000FF" else B"xFF000000"),
    U"01"  -> (if(configPadding.endianess == LITTLE_endian) B"x0000FFFF" else B"xFFFF0000"),
    U"10"  -> (if(configPadding.endianess == LITTLE_endian) B"x00FFFFFF" else B"xFFFFFF00"),
    U"11"  ->  B"xFFFFFFFF"
  )

  val maskSet1 = io.core.cmd.size.mux(
    U"00"  -> (if(configPadding.endianess == LITTLE_endian) B"x00008000" else B"x00800000"),
    U"01"  -> (if(configPadding.endianess == LITTLE_endian) B"x00800000" else B"x00008000"),
    U"10"  -> (if(configPadding.endianess == LITTLE_endian) B"x80000000" else B"x00000080"),
    U"11"  -> B"x00000000"
  )

  /**
    * Padding state machine
    */
  val sm = new StateMachine {

    val addPaddingNextWord = Reg(Bool)
    val isBiggerThan448    = Reg(Bool)
    val fillNewBlock       = Reg(Bool)

    val isLastFullWordInBlock = indexWord === 0 && io.core.cmd.size === (nbrByteInWord-1)

    always{
      when(io.core.init){
        cntBit    := 0
        indexWord := nbrWordInBlock - 1
        block.map(_ := 0)
        goto(sLoad)
      }
    }

    val sLoad: State = new State with EntryPoint{ /* Load the block register of 512-bit */
      whenIsActive{

        addPaddingNextWord := True
        isBiggerThan448    := False
        fillNewBlock       := False

        when(io.core.cmd.valid){

          block(indexWord) := io.core.cmd.msg

          when(io.core.cmd.last){

            cntBit := cntBit + io.core.cmd.size.mux(
              U"00"  ->  8,
              U"01"  -> 16,
              U"10"  -> 24,
              U"11"  -> 32
            )
            when(isLastFullWordInBlock){
              goto(sProcessing)
            }otherwise{
              isBiggerThan448 := indexWord < 2 || (indexWord === 2 && io.core.cmd.size === (nbrByteInWord-1))
              goto(sPadding)
            }
          }otherwise{

            cntBit     := cntBit + configCore.dataWidth.value
            indexWord  := indexWord - 1

            when(indexWord === 0){
              goto(sProcessing)
            }otherwise{
              io.core.cmd.ready := True
            }
          }
        }
      }

      val sPadding: State = new State { /* Do padding  */
        onEntry{

          when(isLastFullWordInBlock || fillNewBlock){
            indexWord     := nbrWordInBlock - 1
            fillNewBlock  := False
          }otherwise{
            block(indexWord) := (io.core.cmd.msg & maskMsg) | maskSet1
            when(indexWord =/= 0)  { indexWord := indexWord - 1 }
            when(io.core.cmd.size =/= (nbrByteInWord-1)){ addPaddingNextWord := False }
          }
        }

        whenIsActive{

          when(indexWord > 1 || isBiggerThan448){

            indexWord := indexWord - 1

            when(addPaddingNextWord){
              block(indexWord)   := (if(configPadding.endianess == LITTLE_endian) B"x00000080" else B"x80000000")
              addPaddingNextWord := False
            }otherwise{
              when(indexWord =/= 0){
                block(indexWord) := B(0).resized
              }
            }

            when(indexWord === 0){
              fillNewBlock := True
              goto(sProcessing)
            }

          }otherwise{

            if(configPadding.endianess == LITTLE_endian){
              block(1) := cntBit(31 downto 0).asBits
              block(0) := cntBit(63 downto 32).asBits
            }else{
              block(0) := cntBit(31 downto 0).asBits
              block(1) := cntBit(63 downto 32).asBits
            }

            goto(sProcessing)
          }
        }
      }

      val sProcessing: State = new State {    /* Run Hash Engine */
        whenIsActive{
          io.engine.cmd.valid := True

          when(io.engine.cmd.ready){

            block.map(_ := 0)

            when(isBiggerThan448 || isLastFullWordInBlock) {
              isBiggerThan448 := False
              goto(sPadding)
            } otherwise {
              io.core.cmd.ready := True
              goto(sLoad)
            }
          }
        }
      }
    }
  }

  io.engine.cmd.message := block.asBits
  io.engine.cmd.valid   := False // default value
  io.engine.init        := io.core.init

  io.core.cmd.ready  := False // default value

  io.core.rsp.digest := io.engine.rsp.digest
  io.core.rsp.valid  := io.engine.rsp.valid && io.core.cmd.last && !sm.isBiggerThan448 && !sm.isLastFullWordInBlock
}