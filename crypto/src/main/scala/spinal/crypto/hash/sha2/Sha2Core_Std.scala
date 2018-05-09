package spinal.crypto.hash.sha2

import spinal.core._
import spinal.lib._

import spinal.crypto.hash._


class Sha2Core_Std {


}


class Sha2Padding_std {

}


/**
  * SHA-2 engine
  *
  * Round : 64 or 80
  *
  * One iteration in a SHA-2
  *
  *    --- --- --- --- --- --- --- ---
  *   | A | B | C | D | E | F | G | H |------------
  *    --- --- --- --- --- --- --- ---             |
  *     |   |   |   |   |   |   |       _____      |       Wt
  *     |   |   |   |   |--------------|     |     |       |
  *     |   |   |   |   |   |----------|  CH |---> + <---- + <--- Kt
  *     |   |   |   |   |   |   |------|_____|     |
  *     |   |   |   |   |   |   |       ______     |
  *     |   |   |   |------------------|_SIG1_|--> +
  *     |   |   |   |   |   |   |                  |
  *     |   |   |   + <----------------------------|      CH   = (E and F) xor (~E and G)
  *     |   |   |   |   |   |   |      ____        |      MA   = (A and B) xor (A and C) xor (B xor C)
  *     |-----------------------------|    |       |      SIG0 = (A >>> 2) xor (A >>> 13) xor (A >>> 2)
  *     |   |-------------------------| Ma |-----> +      SIG1 = (E >>> 6) xor (E >>> 11) xor (E >>> 25)
  *     |   |   |---------------------|___ |       |
  *     |   |   |   |   |   |   |      ______      |
  *     |-----------------------------|_SIG0_|---> +
  *     |   |   |   |   |   |   |                  |
  *     \   \   \   \   \   \   \                  |
  *      \   \   \   \   \   \   \                 |
  *       \   \   \   \   \   \   \                |
  *        \   \   \   \   \   \   \               |
  *    --- --- --- --- --- --- --- ---             |
  *   | A | B | C | D | E | F | G | H |            |
  *    --- --- --- --- --- --- --- ---             |
  *     |_________________________________________/
  *
  *
  */
class Sha2Engine_Std extends Component {

  val io = slave(HashEngineStdIO(512 bits, 256 bits))


  val a, b, c, d, e, f, g, h = Reg(UInt(32 bits))

  val w = Vec(Reg(UInt(32 bits)), 64)

  val cnt = Reg(UInt(6 bits))
  val startExtension   = RegInit(False)
  val startCompression = RegInit(False)
  val finalProcessing  = RegInit(False)
  val isBusy           = RegInit(False)

  val memK = Mem(UInt(32 bits), Sha2CoreSpec.K(256 bits).map(U(_, 32 bits)))
  val memH = Reg(Vec(Sha2CoreSpec.InitHash(256 bits).map(U(_, 32 bits))))

  when(io.init){

    a := U(Sha2CoreSpec.InitHash(256 bits)(0), 32 bits)
    b := U(Sha2CoreSpec.InitHash(256 bits)(1), 32 bits)
    c := U(Sha2CoreSpec.InitHash(256 bits)(2), 32 bits)
    d := U(Sha2CoreSpec.InitHash(256 bits)(3), 32 bits)
    e := U(Sha2CoreSpec.InitHash(256 bits)(4), 32 bits)
    f := U(Sha2CoreSpec.InitHash(256 bits)(5), 32 bits)
    g := U(Sha2CoreSpec.InitHash(256 bits)(6), 32 bits)
    h := U(Sha2CoreSpec.InitHash(256 bits)(7), 32 bits)


    cnt := 0
    startCompression := False
    startExtension   := False
    finalProcessing  := False
  }


  // Initialize working variables to current hash value:
  when(io.cmd.valid && !isBusy){
    for(i <- 0 until 16){
      w(i) := io.cmd.message.subdivideIn(32 bits).reverse(i).asUInt
    }
    //w.slice(0, 14) := io.cmd.message.subdivideIn(32 bits)

    startExtension := True
    isBusy := True
  }


  //  for i from 16 to 63
  //  s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
  //  s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
  //  w[i] := w[i-16] + s0 + w[i-7] + s1

  when(startExtension){
    when(cnt === 15){
      startExtension   := False
      startCompression := True
      cnt := 0
    }otherwise {
      cnt := cnt + 1
    }


    val s0 =  Sha2CoreSpec.SSIG0(w( cnt + 1  ), 256 bits)
    val s1 =  Sha2CoreSpec.SSIG1(w( cnt + 14 ), 256 bits)
    w( cnt + 16 ) := w( cnt ) + s0 + w( cnt + 9 ) + s1
  }

//  for i from 0 to 63
//  S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
//  ch := (e and f) xor ((not e) and g)
//  temp1 := h + S1 + ch + k[i] + w[i]
//  S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
//  maj := (a and b) xor (a and c) xor (b and c)
//  temp2 := S0 + maj
//
//  h := g
//  g := f
//  f := e
//  e := d + temp1
//  d := c
//  c := b
//  b := a
//  a := temp1 + temp2
  when(startCompression){

    when(cnt === 63){
      startCompression := False
      cnt := 0
      finalProcessing := True
    }otherwise{
      cnt := cnt + 1
    }

    val s1    = Sha2CoreSpec.BSIG1(e, 256 bits)
    val ch    = Sha2CoreSpec.CH(e, f, g)
    val temp1 = h + s1 + ch + memK( cnt ) + w( cnt )
    val s0    = Sha2CoreSpec.BSIG0(a, 256 bits)
    val maj   = Sha2CoreSpec.MAJ(a, b, c)
    val temp2 = s0 + maj

    h := g
    g := f
    f := e
    e := d + temp1
    d := c
    c := b
    b := a
    a := temp1 + temp2
  }
//
//  Add the compressed chunk to the current hash value:
//    h0 := h0 + a
//  h1 := h1 + b
//  h2 := h2 + c
//  h3 := h3 + d
//  h4 := h4 + e
//  h5 := h5 + f
//  h6 := h6 + g
//  h7 := h7 + h
  val h0, h1, h2, h3, h4, h5, h6, h7 = Reg(UInt(32 bits))
  when(finalProcessing){
    memH(0) := memH(0) + a
    memH(1) := memH(1) + b
    memH(2) := memH(2) + c
    memH(3) := memH(3) + d
    memH(4) := memH(4) + e
    memH(5) := memH(5) + f
    memH(6) := memH(6) + g
    memH(7) := memH(7) + h

    finalProcessing := False
    isBusy := False
  }

  io.rsp.digest := memH.asBits //(0) ## memH(1) ## memH(2) ## memH(3) ## memH(4) ## memH(5) ## memH(6) ## memH(7)

  io.rsp.valid := finalProcessing.fall(False)

  io.cmd.ready := finalProcessing.fall(False)
//  Produce the final hash value (big-endian):
//    digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7

}

object PlayWithSha2 extends App {

  SpinalConfig(
    mode = VHDL
  ).generate(new Sha2Engine_Std)

}
