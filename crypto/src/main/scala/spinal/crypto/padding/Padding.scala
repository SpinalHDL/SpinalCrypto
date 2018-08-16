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
package spinal.crypto.padding

import spinal.core._
import spinal.lib._


/**
  * Base class for the padding configuration
  * @param dataInWidth    width of the data from the command
  * @param dataOutWidth   width of the data from the response
  * @param symbolInWidth  symbol width of the command data
  */
class PaddingConfig(
  dataInWidth   : BitCount,
  dataOutWidth  : BitCount,
  symbolInWidth : BitCount
){
  def getPaddingIOConfig = PaddingIOConfig(
    dataCmdWidth = dataInWidth,
    dataRspWidth = dataOutWidth,
    symbolWidth  = symbolInWidth
  )
}


case class PaddingIOConfig (
  dataCmdWidth  : BitCount,
  dataRspWidth  : BitCount,
  symbolWidth   : BitCount = 8 bits
)

case class PaddingIO_Cmd(dataWidth: BitCount, symbolWidth: BitCount) extends Bundle{
  val data = Bits(dataWidth)
  val size = UInt(log2Up(dataWidth.value / symbolWidth.value) bits)
}

case class PaddingIO_Rsp(dataWidth: BitCount) extends Bundle{
  val data = Bits(dataWidth)
}


case class PaddingIO(config: PaddingIOConfig) extends Bundle with IMasterSlave{

  val init = Bool
  val cmd  = Stream(Fragment(PaddingIO_Cmd(config.dataCmdWidth, config.symbolWidth)))
  val rsp  = Stream(Fragment(PaddingIO_Rsp(config.dataRspWidth)))

  override def asMaster(): Unit = {
    out(init)
    master(cmd)
    slave(rsp)
  }
}