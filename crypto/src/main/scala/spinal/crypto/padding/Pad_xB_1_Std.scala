package spinal.crypto.padding

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._


case class Padding_xB_1_Config(
  dataInWidth  : BitCount,
  dataOutWidth : BitCount ,
  pad_xB       : Byte,
  symbolWidth  : BitCount = 8 bits
)


case class Padding_Cmd(dataWidth: BitCount, symbolWidth: BitCount) extends Bundle{
  val data = Bits(dataWidth)
  val size = UInt(log2Up(dataWidth.value / symbolWidth.value) bits)
}

case class Padding_Rsp(dataWidth: BitCount) extends Bundle{
  val data = Bits(dataWidth)
}


/**
  * Padding xB* 1 (message is byte-aligned)
  *
  * e.g. with xPad = 0x06
  *
  *     +--------------------------------+
  *     |       Padded message           |
  *     ---------------------------------+
  *     |  M || 0x86                     |
  *     |  M || 0x0680                   |
  *     |  M || 0x06 || 0x00... || 0x80  |
  *     +--------------------------------+
  *
  */
class Pad_xB_1_Std(config: Padding_xB_1_Config) extends Component {

  assert(config.dataInWidth.value == 32, "Currently padding supports only 32 bits")
  assert(config.symbolWidth.value == 8,  "Padding works in byte")

  val io = new Bundle{
    val init = in Bool
    val cmd  = slave(Stream(Fragment(Padding_Cmd(config.dataInWidth, config.symbolWidth))))
    val rsp  = master(Stream(Fragment(Padding_Rsp(config.dataOutWidth))))
  }

  val nbrElementInBlock = config.dataOutWidth.value / config.dataInWidth.value
  val buffer            = Reg(Vec(Bits(config.dataInWidth), nbrElementInBlock))
  val indexBuffer       = Reg(UInt(log2Up(nbrElementInBlock) bits))

  io.cmd.ready := False
  io.rsp.valid := False
  io.rsp.data  := Cat(buffer.reverse)
  io.rsp.last  := io.cmd.valid & io.cmd.last


  val mask_1 = io.cmd.size.mux(
    U"00" -> B("x00"     + f"${config.pad_xB}%02X0000"),
    U"01" -> B("x0000"   + f"${config.pad_xB}%02X00"),
    U"10" -> B("x000000" + f"${config.pad_xB}%02X"),
    U"11" -> B("x"       + f"${config.pad_xB}%02X000000")
  )

  /**
    * Padding state machine
    */
  val sm = new StateMachine {

    val add_1_nextElement = Reg(Bool)
    val fillNewBlock      = Reg(Bool)

    always{
      when(io.init){
        indexBuffer  := 0
        add_1_nextElement := False
        fillNewBlock := False
        buffer.map(_ := 0)
        goto(sLoad)
      }
    }

    val sLoad: State = new State with EntryPoint{
      whenIsActive{

        when(io.cmd.valid){

          buffer(indexBuffer) := io.cmd.data

          when(io.cmd.last){
            goto(sPadding_1)
          }otherwise{
            indexBuffer  := indexBuffer + 1

            when(indexBuffer === nbrElementInBlock - 1){
              goto(sProcessing)
            }otherwise{
              io.cmd.ready := True
            }
          }
        }
      }

      val sPadding_1: State = new State{
        whenIsActive{

          when(io.cmd.size === 3){
            add_1_nextElement := True
          }otherwise{
            buffer(indexBuffer) := buffer(indexBuffer) | mask_1
          }
          goto(sPadding)
        }
      }

      val sPadding: State = new State {
        whenIsActive{
          when(fillNewBlock){
            buffer(0)   := mask_1
            buffer.last := B"x00000080"
            fillNewBlock      := False
            add_1_nextElement := False
            goto(sProcessing)
          }elsewhen(add_1_nextElement){
            when(indexBuffer === nbrElementInBlock - 1){
              fillNewBlock := True
              goto(sProcessing)
            }otherwise{
              buffer(indexBuffer + 1) := mask_1
              add_1_nextElement := False
            }
          }otherwise{
            buffer.last := buffer.last | B"x00000080"
            goto(sProcessing)
          }
        }
      }

      val sProcessing: State = new State {    /* Run Algorithm */
        whenIsActive{
          io.rsp.valid := True

          when(io.rsp.ready){
            buffer.map(_ := 0)
            indexBuffer := 0
            when(fillNewBlock){
              goto(sPadding_1)
            }otherwise{
              io.cmd.ready := True
              goto(sLoad)
            }
          }
        }
      }
    }
  }
}