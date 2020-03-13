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
package spinal.crypto.checksum.sim

import spinal.core._
import spinal.core.sim._
import spinal.crypto.checksum.{CRCCombinationalCmdMode, CRCCombinationalIO}


object CRCCombinationalsim {

  def doSim(dut: CRCCombinationalIO, clockDomain: ClockDomain, data: List[BigInt], verbose: Boolean = false)(result: BigInt): Unit = {

    require(data.length > 0)

    var index = 0

    // initialize value
    dut.cmd.valid #= false
    dut.cmd.mode  #= CRCCombinationalCmdMode.INIT
    dut.cmd.data  #= 0

    // Wait end reset
    clockDomain.waitActiveEdge()

    // init CRC
    dut.cmd.valid #= true
    clockDomain.waitActiveEdge()
    dut.cmd.valid #= false
    clockDomain.waitActiveEdge()

    // Send all data
    for(_ <- 0 until data.length){
      dut.cmd.mode  #= CRCCombinationalCmdMode.UPDATE
      dut.cmd.valid #= true
      dut.cmd.data  #= data(index)

      clockDomain.waitActiveEdge()

      dut.cmd.valid #= false

      clockDomain.waitActiveEdge()

      index += 1
    }

    // check crc
    val crcRTL = dut.crc.toBigInt

    if(verbose){
      println(s"0x${crcRTL.toString(16).toUpperCase}")
    }

    assert(crcRTL == result, "CRC error")
  }
}
