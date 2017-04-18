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
package spinalcrypto.symmetric.des

import spinal.core._
import spinal.lib.fsm._
import spinalcrypto.symmetric.{SymmetricCryptoBlockGeneric, SymmetricCryptoBlockIO}


/**
  * Triple DES (3DES)
  *
  *           Encrpytion :                Decrytpion :
  *
  *           plaintext                   plaintext      (64 bits)
  *               |                           |
  *       -----------------            ----------------
  *      |   DES encrypt   |<-- K1 -->|  DES decrypt   |
  *       -----------------            ----------------
  *               |                           |
  *       -----------------            ----------------
  *      |   DES decrypt   |<-- K2 -->|  DES encrypt   |
  *       -----------------            ----------------
  *               |                           |
  *       -----------------            ----------------
  *      |   DES encrypt   |<-- K3 -->|  DES decrypt   |
  *       -----------------            ----------------
  *               |                           |
  *           ciphertext                   ciphertext      (64 bits)
  *
  *
  *    key = Concatenation(k1 , k2 , k3) = 3*64 bits = 192 bits
  *
  */
class TripleDESCore() extends Component{

  val gIO  = SymmetricCryptoBlockGeneric(keyWidth   = ((DESCoreSpec.keyWidth.value + DESCoreSpec.keyWidthParity.value) * 3) bits,
                                         blockWidth = DESCoreSpec.blockWidth,
                                         useEncDec  = true)

  val io = new SymmetricCryptoBlockIO(gIO)

  val block = Reg(Bits(DESCoreSpec.blockWidth))

  val coreDES = new DESCore()

  /**
    * Triple DES state machine
    */
  val sm3DES = new StateMachine{

    val desCmdValid = False
    val desEncDec   = False
    val desKey      = B(0, DESCoreSpec.keyWidthParity + DESCoreSpec.keyWidth)
    val inSel       = False
    val cmdReady    = False

    val sIdle: State = new State with EntryPoint{
      whenIsActive{
        when(io.cmd.valid && !io.cmd.ready){
          goto(sStage1)
        }
      }
    }

    val sStage1: State = new State{
      whenIsActive{
        desEncDec   := io.cmd.enc
        desCmdValid := True
        desKey      := io.cmd.enc ? io.cmd.key(191 downto 128) | io.cmd.key(63 downto 0)

        when(coreDES.io.rsp.valid){
          desCmdValid := False
          block       := coreDES.io.rsp.block
          goto(sStage2)
        }
      }
    }

    val sStage2: State = new State{
      whenIsActive{
        inSel       := True
        desEncDec   := !io.cmd.enc
        desKey      := io.cmd.key(127 downto 64)
        desCmdValid := True

        when(coreDES.io.rsp.valid){
          desCmdValid := False
          block       := coreDES.io.rsp.block
          goto(sStage3)
        }
      }
    }

    val sStage3: State = new State{
      whenIsActive{
        inSel       := True
        desEncDec   := io.cmd.enc
        desKey      := io.cmd.enc ? io.cmd.key(63 downto 0) | io.cmd.key(191 downto 128)
        desCmdValid := True

        when(coreDES.io.rsp.valid){
          desCmdValid := False
          cmdReady    := True
          block       := coreDES.io.rsp.block
          goto(sIdle)
        }
      }
    }
  }


  /*
   * DES block connection
   */
  coreDES.io.cmd.valid  <> sm3DES.desCmdValid
  coreDES.io.cmd.key    <> sm3DES.desKey
  coreDES.io.cmd.enc    <> sm3DES.desEncDec
  coreDES.io.cmd.block  <> (sm3DES.inSel ? block | io.cmd.block)


  /*
   * Output
   */
  val cmdReady = RegNext(sm3DES.cmdReady, False)
  io.rsp.block := block
  io.rsp.valid := cmdReady
  io.cmd.ready := cmdReady
}



