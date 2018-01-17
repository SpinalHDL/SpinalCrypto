package cryptotest


import org.scalatest.FunSuite
import ref.mac.HMAC

import spinal.core._
import spinal.crypto.{BigIntToHexString, Endianness, CastByteArray}
import spinal.crypto.hash.md5.MD5Core_Std
import spinal.crypto.mac.hmac.{HMACCoreStdIO, HMACCoreStdGeneric, HMACCore_Std}

import spinal.lib.slave

import spinal.sim._
import spinal.core.sim._

import scala.util.Random


class HMACCoreStd_MD5_Tester() extends Component {

  val md5  = new MD5Core_Std()
  val hmac = new HMACCore_Std(HMACCoreStdGeneric(md5.g.hashBlockWidth, md5.g))

  val io = slave(HMACCoreStdIO(hmac.g))

  hmac.io.hmacCore <> io
  hmac.io.hashCore <> md5.io
}



class SpinalSimHMACCoreStdTester extends FunSuite {

  // RTL to simulate
  val compiledRTL = SimConfig.compile(new HMACCoreStd_MD5_Tester())


  /**
    * Test
    */
  test("HMACCoreStd_MD5"){

    compiledRTL.doSim{ dut =>

      val byteSizeMsg = dut.io.cmd.msg.getWidth / 8

      dut.clockDomain.forkStimulus(2)

      // initialize value
      dut.io.init       #= false
      dut.io.cmd.valid  #= false

      dut.clockDomain.waitActiveEdge()

      var lenMsg = 1

      Suspendable.repeat(200){

        var msgStr = (List.fill(lenMsg)(Random.nextPrintableChar()).mkString(""))
        val keyStr = (List.fill(64)(Random.nextPrintableChar()).mkString(""))

//        var msgStr = """RYWc/tA]1iG)lj3xlszyvbg+'4.y'wttA+:O`TsOh(yOo3v{j!.n4$Q+kW1$@'@=J%L%G')Nx#@D:SZ0/I!g91d?v1w$bWV|dE;{zKdMy(91WTX.w-r_6-6OHB}60EcVQWNfmzeQ!ebPep~`8Y`bM&BabXGiF;xHD4Imb+}#(x"RhB[JcTWA|LTu-r4(TYD%ul*M~B{*_~k0!KsJ'0iJk_aZ=^~og.1(J7,)|716bIoT;WU=vxw=8^OZhX9up1dS>@[NIgcj%-)o1W%10.$9aZUC_0bk^9~KL%<XyOu8$seiS8D27DlKs+RWjEs=EH1@xlOlL&F9Z]N_~o3b4~63q,ODo=YHC_o*4D.3#1KmX7p`qm{M:H?fVxUgCbx$3E@#[7_Vjf0_L:,-MJw)s')3&@5vfeQC|P13k?#^P<`m#vvXSD`4C6SmybZ@c$h&tir#-j(?DBuvKYrblBQQ5q#ScTcB%#_$[5Bckce@T8R}:r1XPs~48o#(+;yk;gH%ue^qitYRqN|yeI0Y9J#aVc`j~i~X"$oGhA9,l_^dAaxn}4>NufMKGlnl]|u3QNzbx?Nk;-^;c9)3XunL0+H1wF&"%<TA|v%=LM&(>vsMA|24NKFHTfXW/O"4Br4N-BJIO6tf-,{y^tX[pqHzzD&~^kH8d+E@M>a<tXgw3'xN3}zLn`Q?>y,TV'.`w|X.$E[vqGZ=D@2sXQ!tXXt.U$#5%C|B.5uk*)IuNP4Vi|e{r.l7o"CCpxtn>!v{pcXES*cL_Zx)J#MF{tfzteg[S]D%`$!6>arw1ADnI|6vo+&7kq$1oulz,~TM8H[]Rl71.^|QcTr%W"B"AIIrb1Wr|f[w_;1&2$+p)I[kFMo~@Ft#hHIs!XbA<-:,pH+(P1G|0>L7R<5awF"""
//        val keyStr = """0,m,U/s_^QYBFOWyy=dIpde<)s#13u/&7S:Xn[Y`Eu}<.|?<&DnTk#0q_R5-:,L*"""
        val msgStrOrginal = msgStr


        val refHmac = HMAC.digest(msgStr, keyStr, "HmacMD5")

        val keyByte = Endianness((keyStr.map(_.toByte).toList ::: List.fill(((dut.io.cmd.key.getWidth / 4) - keyStr.length * 2) / 2 )(0.toByte)).toArray)

        // init HMAC
        dut.clockDomain.waitActiveEdge()
        dut.io.init      #= true
        dut.clockDomain.waitActiveEdge()
        dut.io.init      #= false
        dut.clockDomain.waitActiveEdge()

        // number of iteration
        var index = math.ceil(msgStr.length  / byteSizeMsg.toDouble).toInt

        // Send all block of message
        while(index != 0) {

          val (msg, isLast) = if (msgStr.length > byteSizeMsg) (msgStr.substring(0, byteSizeMsg) -> false) else (msgStr + 0.toChar.toString * (byteSizeMsg - msgStr.length) -> true)

          val msgByte = Endianness(msg.map(_.toByte).toArray)

          dut.io.cmd.valid #= true
          dut.io.cmd.msg   #= BigInt(0x00.toByte +: msgByte)
          dut.io.cmd.size  #= BigInt(if (isLast) msgStr.length - 1 else 0)
          dut.io.cmd.last  #= isLast
          dut.io.cmd.key   #= BigInt(0x00.toByte +: keyByte)


          // Wait the response
          if (isLast){
            waitUntil(dut.io.rsp.valid.toBoolean == true)

            val rtlHmac = CastByteArray(dut.io.rsp.hmac.toBigInt.toByteArray, dut.io.rsp.hmac.getWidth / 8)

            assert(
              refHmac == BigInt(Endianness(rtlHmac)),
              s"""
                 | REF != RTL    : ${BigIntToHexString(refHmac)} != ${BigIntToHexString(BigInt(0x00.toByte +: Endianness(rtlHmac)))}"
                 | Input message : ${msgStrOrginal}
                 | Key           : ${keyStr}
               """.stripMargin
            )

            dut.clockDomain.waitActiveEdge()
          }else {
            waitUntil(dut.io.cmd.ready.toBoolean == true)

            dut.clockDomain.waitActiveEdge()
          }

          dut.io.cmd.valid #= false

          dut.clockDomain.waitActiveEdge()

          index -= 1
          msgStr = msgStr.drop(byteSizeMsg)
        }

        lenMsg += 1
      }
    }
  }

}