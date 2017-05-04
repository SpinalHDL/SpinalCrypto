/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/                                   **
**                                                                           **
**      This library is free software; you can redistribute it and/or        **
**    modify it under the terms of the GNU Lesser General Public             **
**    License as published by the Free Software Foundation; either           **
**    version 3.0 of the License, or (at your option) any later version.     **
**                                                                           **
**      This library is distributed in the hope that it will be useful,      **
**    but WITHOUT ANY WARRANTY; without even the implied warranty of         **
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      **
**    Lesser General Public License for more details.                        **
**                                                                           **
**      You should have received a copy of the GNU Lesser General Public     **
**    License along with this library.                                       **
\*                                                                           */
package spinalcrypto.hash.md5

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._

import scala.math.{pow, sin}


case class MD5CoreStdCmd() extends Bundle{
  val msg  = Bits(32 bits)
  val size = UInt(3 bits)
}

case class MD5CoreStdRsp() extends Bundle{
  val hash = Bits(MD5CoreSpec.hashSize)
}

class MD5Core_Std() extends Component{

  val io = new Bundle{
    val init = in Bool
    val cmd  = slave Stream(Fragment(MD5CoreStdCmd()))
    val rsp  = master Flow(MD5CoreStdRsp())
  }

  val cntBit    = Reg(UInt(64 bits))
  val block     = Reg(Vec(Bits(32 bits), 16))
  val indexWord = Reg(UInt(4 bits))

  val engine = new MD5Engine_Std()


  val sm = new StateMachine{

    val add1 = Reg(Bool)
    val is448 = Reg(Bool)
    val fillNewBlock = Reg(Bool)

    always{
      when(io.init){
        cntBit := 0
        indexWord := 15
        goto(sLoad)
      }
    }

    val sLoad: State = new State with EntryPoint{
      whenIsActive{

        add1 := True
        is448 := False
        fillNewBlock := False

        when(io.cmd.valid){

          when(io.cmd.last){
            cntBit := cntBit + io.cmd.size.mux(
              U"000"  ->  0,
              U"001"  ->  8,
              U"010"  -> 16,
              U"011"  -> 24,
              U"100"  -> 32,
              default -> 0
            )

            when(indexWord <= 2){ is448 := True }

            goto(sPadding)

          }otherwise{
            cntBit           := cntBit + 32
            indexWord        := indexWord - 1
            block(indexWord) := io.cmd.msg
            io.cmd.ready     := True
          }
        }
      }

      val sPadding: State = new State{
        onEntry{
          val mask = io.cmd.size.mux(
            U"000"  -> B"x00000000",
            U"001"  -> B"x000000FF",
            U"010"  -> B"x0000FFFF",
            U"011"  -> B"x00FFFFFF",
            U"100"  -> B"xFFFFFFFF",
            default -> B"x00000000"
          )
          val mask1 = io.cmd.size.mux(
            U"000"  -> B"x00000080",
            U"001"  -> B"x00008000",
            U"010"  -> B"x00800000",
            U"011"  -> B"x80000000",
            U"100"  -> B"x00000000",
            default -> B"x00000000"
          )

          when(!fillNewBlock){
            block(indexWord) := (io.cmd.msg & mask) | mask1
            indexWord := indexWord - 1
            when(io.cmd.size =/= 4){ add1 := False }
          }otherwise{
            block(indexWord) := 1
            fillNewBlock := False
          }
        }
        whenIsActive{
          when(indexWord > 1 || is448){ // less than 448 bits

            indexWord := indexWord - 1

            when(add1){
              block(indexWord) := B"x00000080"
              add1 := False
            }otherwise {
              block(indexWord) := 0
            }

            when(indexWord === 0 && is448){
              fillNewBlock:= True
              goto(sProcessing)
            }

          }otherwise{
            block(1) := cntBit(31 downto 0).asBits
            block(0) := cntBit(63 downto 32).asBits
            goto(sProcessing)
          }
        }
      }

      val sProcessing: State = new State{
        whenIsActive{

          engine.io.cmd.valid := True

          when(engine.io.cmd.ready){

            when(is448){
              indexWord := 15
              is448:= False
              goto(sPadding)
            }otherwise {
              io.cmd.ready := True
              goto(sLoad)
            }
          }

        }
      }
    }
  }


  engine.io.cmd.block := block.asBits
  engine.io.cmd.valid := False

  engine.io.init := io.init


  io.cmd.ready := False

  io.rsp.hash  := engine.io.rsp.hash
  io.rsp.valid := engine.io.rsp.valid && io.cmd.payload.last && !sm.is448

}


object PlayWithCore{
  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new MD5Core_Std).printPruned
  }
}


/**
  * MD5 core command
  */
case class MD5EngineStdCmd() extends Bundle{
  val block = Bits(MD5CoreSpec.msgBlockSize)
}

/**
  * MD5 core response
  */
case class MD5EngineStdRsp() extends Bundle{
  val hash = Bits(MD5CoreSpec.hashSize)
}


/**
  * The MD5 algorithm is a hash function producing a 128-bit hash value. MD5 works with block of 512-bit. The message to
  * hash must be padded as following:
  *    - Add a one bit a the end of the message
  *    - Add a sequence of 0 until to get a block of 448-bits
  *    - Write the size in bits of the message on 64 bits (l0 l1) e.g : 24 bits => 00000018 00000000
  *
  * !!!!! MD5 works in little-Endian !!!!!!!
  *
  * doc : https://www.ietf.org/rfc/rfc1321.txt
  *
  * msgBlock
  *(512 bits)
  *    |     _______ _______ _______ _______
  *    |    |  ivA  |  ivB  |  ivC  |  ivD  |<------\
  *    |     ------- ------- ------- -------  --\   |
  *    |        |       |      |        |       |   |
  *    |        A       B      C        D       |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    |--->|         16 iterations         |   |   |
  *    |     -------------------------------    |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    |--->|         16 iterations         |   |   |
  *    |     -------------------------------    |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    |--->|         16 iterations         |   |   |
  *    |     -------------------------------    |   |
  *    |        |       |      |        |       |   |
  *    |     _______________________________    |   |
  *    \--->|         16 iterations         |   |   |
  *          -------------------------------    |   |
  *             |       |      |        |       |   |
  *             + <---- + <--- + <----- + <-----/   |
  *             |       |      |        |           |
  *          _______________________________        |
  *         |         128 bits Hash         |-------/
  *          -------------------------------
  *
  */
class MD5Engine_Std extends Component{

  val io = new Bundle{
    val init = in Bool
    val cmd  = slave Stream(MD5EngineStdCmd())
    val rsp  = master Flow(MD5EngineStdRsp())
  }

  val ivA   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val ivB   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val ivC   = Reg(Bits(MD5CoreSpec.subBlockSize))
  val ivD   = Reg(Bits(MD5CoreSpec.subBlockSize))

  val memT  = Mem(UInt(32 bits), MD5CoreSpec.constantT.map(U(_, 32 bits)))
  val memK  = Mem(UInt(4 bits),  MD5CoreSpec.indexK.map(U(_, 4 bits)))

  val memS  = List(Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(0,  4).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(4,  8).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(8, 12).map(U(_, 5 bits))),
                   Mem(UInt(5 bits),  MD5CoreSpec.shiftCstS.slice(12,16).map(U(_, 5 bits))))

  /**
    * Iterative round:
    *
    * X : message block (512 bits)
    * T : constant table (32 bits)
    * A, B, C, D : 32 bits
    *         _______ _______ _______ _______
    *        |   A   |   B   |   C   |   D   |
    *         ------- ------- ------- -------
    *             |     |  \____   |   ___|
    *             |     |      _\__|__/_
    *             + ----------|   Func  | (Func: F, G, H, I)
    *             |     |      ---------
    *    X[k] --> +     |
    *             |     |
    *    T[i] --> +     |
    *             |     |
    *            << S   |     (left rotation)
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
  val iterativeRound = new Area{

    val i = Reg(UInt(6 bits))

    val endIteration = i === 63

    /* Register block */
    val blockA   = Reg(Bits(MD5CoreSpec.subBlockSize))
    val blockB   = Reg(Bits(MD5CoreSpec.subBlockSize))
    val blockC   = Reg(Bits(MD5CoreSpec.subBlockSize))
    val blockD   = Reg(Bits(MD5CoreSpec.subBlockSize))

    /* Block signals */
    val sblockA = B(0, MD5CoreSpec.subBlockSize)
    val sblockB = B(0, MD5CoreSpec.subBlockSize)
    val sblockC = B(0, MD5CoreSpec.subBlockSize)
    val sblockD = B(0, MD5CoreSpec.subBlockSize)

    // mux to select among the three function F, G, H, I
    val selFunc = B(0, 2 bits)
    val funcResult = selFunc.mux(B"00" -> MD5CoreSpec.funcF(blockB, blockC, blockD),
                                 B"01" -> MD5CoreSpec.funcG(blockB, blockC, blockD),
                                 B"10" -> MD5CoreSpec.funcH(blockB, blockC, blockD),
                                 B"11" -> MD5CoreSpec.funcI(blockB, blockC, blockD))

    // Cut the message block into 32 bits
    val k = memK(i)
    val wordBlock = k.muxList(for(index <- 0 until 16) yield (15-index, io.cmd.block(index*32+32-1 downto index*32)))

    // Select among the 4 memShift memory
    val shiftValue = selFunc.muxList(for(index <- 0 until 4) yield (index, memS(index)(i(1 downto 0)) ))

    // Compute the new value of the B block
    val newBlockB = (funcResult.asUInt + blockA.asUInt + wordBlock.asUInt + memT(i)).rotateLeft(shiftValue) + blockB.asUInt




    // last round => add the initial vector to the current block
    when(endIteration){
      sblockA := (blockD.asUInt + ivA.asUInt).asBits
      sblockB := (newBlockB     + ivB.asUInt).asBits
      sblockC := (blockB.asUInt + ivC.asUInt).asBits
      sblockD := (blockC.asUInt + ivD.asUInt).asBits
    }otherwise{
      // Update the new value of block A, B, C, D
      sblockA := blockD
      sblockB := newBlockB.asBits
      sblockC := blockB
      sblockD := blockC
    }

    // Register signal block
    when(io.cmd.valid){
      blockA  := sblockA
      blockB  := sblockB
      blockC  := sblockC
      blockD  := sblockD
    }
  }


  /**
    * MD5 controller
    */
  val ctrlMD5 = new Area {

    val isProcessing = Reg(Bool) init(False)

    when(io.init){
      iterativeRound.blockA := MD5CoreSpec.initBlockA
      iterativeRound.blockB := MD5CoreSpec.initBlockB
      iterativeRound.blockC := MD5CoreSpec.initBlockC
      iterativeRound.blockD := MD5CoreSpec.initBlockD
      iterativeRound.i := 0
      isProcessing     := False
    }.elsewhen(io.cmd.valid && !isProcessing && !io.cmd.ready){
      isProcessing := True
      ivA := iterativeRound.blockA
      ivB := iterativeRound.blockB
      ivC := iterativeRound.blockC
      ivD := iterativeRound.blockD
      iterativeRound.i := iterativeRound.i + 1
    }

    when(isProcessing){

      iterativeRound.i := iterativeRound.i + 1

      when(iterativeRound.i < 16){
        iterativeRound.selFunc := B"00"
      }.elsewhen(iterativeRound.i < 32){
        iterativeRound.selFunc := B"01"
      }.elsewhen(iterativeRound.i < 48){
        iterativeRound.selFunc := B"10"
      }.otherwise{
        iterativeRound.selFunc := B"11"
      }

      when(iterativeRound.endIteration){
        isProcessing := False
      }
    }
  }

  /*
   * Drive the output signals
   */
  io.rsp.hash := iterativeRound.sblockA ## iterativeRound.sblockB ## iterativeRound.sblockC ## iterativeRound.sblockD
  io.rsp.valid  := iterativeRound.endIteration
  io.cmd.ready  := iterativeRound.endIteration
}