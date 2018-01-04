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
package spinal.crypto.hash.md5

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._
import spinal.crypto.hash._


/**
  * MD5Core_Std component
  *
  * !!!!! MD5 works in little-Endian !!!!!!!
  *
  * MD5 specification : https://www.ietf.org/rfc/rfc1321.txt
  *
  */
class MD5Core_Std(dataWidth: BitCount = 32 bits) extends Component{

  val g =  HashCoreGeneric(dataWidth      = dataWidth,
                           hashWidth      = MD5CoreSpec.hashWidth,
                           hashBlockWidth = MD5CoreSpec.blockWidth)

  val io = slave(HashCoreIO(g))

  val engine  = new MD5Engine_Std()
  val padding = new MD5Padding_Std(g)

  padding.io.engine  <> engine.io
  padding.io.core    <> io
}


/**
  * The message to hash must be padded as following:
  *    - Add a one bit a the end of the message
  *    - Add a sequence of 0 until to get a block of 448-bits
  *    - Write the size in bits of the message on 64 bits (l0 l1) e.g : 24 bits => 00000018 00000000
  *
  */
class MD5Padding_Std(g: HashCoreGeneric) extends Component{

  assert(g.dataWidth.value == 32, "Currently MD5Core_Std supports only 32 bits")

  val io = new Bundle{
    val core    = slave(HashCoreIO(g))
    val engine  = master(MD5EngineStdIO())
  }

  val nbrWordInBlock = MD5CoreSpec.blockWidth.value / g.dataWidth.value
  val nbrByteInWord  = g.dataWidth.value / 8

  val cntBit         = Reg(UInt(MD5CoreSpec.cntBitWidth))
  val block          = Reg(Vec(Bits(g.dataWidth), nbrWordInBlock))
  val indexWord      = Reg(UInt(log2Up(nbrWordInBlock) bits))


  val maskMsg = io.core.cmd.size.mux(U"00"  -> B"x000000FF",
                                     U"01"  -> B"x0000FFFF",
                                     U"10"  -> B"x00FFFFFF",
                                     U"11"  -> B"xFFFFFFFF")

  val maskSet1 = io.core.cmd.size.mux(U"00"  -> B"x00008000",
                                      U"01"  -> B"x00800000",
                                      U"10"  -> B"x80000000",
                                      U"11"  -> B"x00000000")

  /**
    * Padding state machine
    */
  val sm = new StateMachine{

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

            cntBit := cntBit + io.core.cmd.size.mux(U"00"  ->  8,
                                                    U"01"  -> 16,
                                                    U"10"  -> 24,
                                                    U"11"  -> 32)
            when(isLastFullWordInBlock){
              goto(sProcessing)
            }otherwise{
              isBiggerThan448 := indexWord < 2 || (indexWord === 2 && io.core.cmd.size === (nbrByteInWord-1))
              goto(sPadding)
            }
          }otherwise{

            cntBit     := cntBit + g.dataWidth.value
            indexWord  := indexWord - 1

            when(indexWord === 0){
              goto(sProcessing)
            }otherwise{
              io.core.cmd.ready := True
            }
          }
        }
      }

      val sPadding: State = new State{ /* Do padding  */
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
              block(indexWord)   := B"x00000080"
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
            block(1) := cntBit(31 downto 0).asBits
            block(0) := cntBit(63 downto 32).asBits
            goto(sProcessing)
          }
        }
      }

      val sProcessing: State = new State{   /* Run MD5 Engine */
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

  io.engine.cmd.block := block.asBits
  io.engine.cmd.valid := False // default value
  io.engine.init      := io.core.init

  io.core.cmd.ready := False // default value

  io.core.rsp.digest := io.engine.rsp.digest
  io.core.rsp.valid  := io.engine.rsp.valid && io.core.cmd.last && !sm.isBiggerThan448 && !sm.isLastFullWordInBlock
}


/**
  * MD5 Engine command
  */
case class MD5EngineStdCmd() extends Bundle{
  val block = Bits(MD5CoreSpec.blockWidth)
}


/**
  * MD5 Engine response
  */
case class MD5EngineStdRsp() extends Bundle{
  val digest = Bits(MD5CoreSpec.hashWidth)
}


/**
  * MD5 Engine IO
  */
case class MD5EngineStdIO() extends Bundle with IMasterSlave{

  val init = Bool
  val cmd  = Stream(MD5EngineStdCmd())
  val rsp  = Flow(MD5EngineStdRsp())

  override def asMaster() = {
    out(init)
    master(cmd)
    slave(rsp)
  }
}


/**
  * The MD5 engine take as input a block message of 512 bits and produce a hash value of 128 bits
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

  val io = slave(MD5EngineStdIO())

  val ivA   = Reg(Bits(MD5CoreSpec.subBlockWidth))
  val ivB   = Reg(Bits(MD5CoreSpec.subBlockWidth))
  val ivC   = Reg(Bits(MD5CoreSpec.subBlockWidth))
  val ivD   = Reg(Bits(MD5CoreSpec.subBlockWidth))

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
    val blockA   = Reg(Bits(MD5CoreSpec.subBlockWidth))
    val blockB   = Reg(Bits(MD5CoreSpec.subBlockWidth))
    val blockC   = Reg(Bits(MD5CoreSpec.subBlockWidth))
    val blockD   = Reg(Bits(MD5CoreSpec.subBlockWidth))

    /* Block signals */
    val sblockA = B(0, MD5CoreSpec.subBlockWidth)
    val sblockB = B(0, MD5CoreSpec.subBlockWidth)
    val sblockC = B(0, MD5CoreSpec.subBlockWidth)
    val sblockD = B(0, MD5CoreSpec.subBlockWidth)

    // mux to select among the three function F, G, H, I
    val selFunc = B(0, 2 bits)
    val funcResult = selFunc.mux(B"00" -> MD5CoreSpec.funcF(blockB, blockC, blockD),
                                 B"01" -> MD5CoreSpec.funcG(blockB, blockC, blockD),
                                 B"10" -> MD5CoreSpec.funcH(blockB, blockC, blockD),
                                 B"11" -> MD5CoreSpec.funcI(blockB, blockC, blockD))

    // Cut the message block into 32 bits
    val k = memK(i)
    val wordBlock = io.cmd.block.subdivideIn(32 bits).reverse(k)

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

    val isProcessing = Reg(Bool)

    when(io.init){
      iterativeRound.blockA := MD5CoreSpec.initBlockA
      iterativeRound.blockB := MD5CoreSpec.initBlockB
      iterativeRound.blockC := MD5CoreSpec.initBlockC
      iterativeRound.blockD := MD5CoreSpec.initBlockD
      iterativeRound.i      := 0
      isProcessing          := False
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
  io.rsp.digest := iterativeRound.sblockA ## iterativeRound.sblockB ## iterativeRound.sblockC ## iterativeRound.sblockD
  io.rsp.valid  := iterativeRound.endIteration
  io.cmd.ready  := iterativeRound.endIteration
}