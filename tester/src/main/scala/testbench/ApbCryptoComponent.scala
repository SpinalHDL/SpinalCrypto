package testbench

import spinal.core._
import spinal.crypto.hash.md5.MD5Core_Std
import spinal.crypto.mac.hmac.{HMACCoreStdConfig, HMACCore_Std}
import spinal.crypto.symmetric.aes.AESCore_Std
import spinal.crypto.checksum._
import spinal.lib._
import spinal.crypto.symmetric.des.{DESCore_Std, TripleDESCore_Std}
import spinal.lib.bus.amba3.apb.{Apb3, Apb3Config, Apb3SlaveFactory}





object Apb3_TestBenchConfig{
  def getApb3Config = Apb3Config(
    addressWidth  = 8,
    dataWidth     = 32,
    selWidth      = 1,
    useSlaveError = false
  )
}

trait ApbCryptoComponent {
  def bus: Apb3
}

case class Apb3_3DESCore_Std() extends Component with ApbCryptoComponent {

  val io = new Bundle {
    val apb = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val desCore = new TripleDESCore_Std()

  val busCtrl = Apb3SlaveFactory(io.apb)
  desCore.io.driveFrom(busCtrl)

  override def bus = io.apb
}


case class Apb3_DESCore_Std() extends Component with ApbCryptoComponent {

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val desCore = new DESCore_Std()

  val busCtrl = Apb3SlaveFactory(io.apb)
  desCore.io.driveFrom(busCtrl)

  override def bus = io.apb
}


case class Apb3_AESCore_Std(keySize: BitCount) extends Component with ApbCryptoComponent {
  val io = new Bundle{
    val apb = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val aesCore = new AESCore_Std(keySize)

  val busCtrl = Apb3SlaveFactory(io.apb)
  aesCore.io.driveFrom(busCtrl)

  override def bus = io.apb
}


case class Apb3_MD5Core_Std() extends Component with ApbCryptoComponent {

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val md5Core = new MD5Core_Std()

  val busCtrl = Apb3SlaveFactory(io.apb)
  md5Core.io.driveFrom(busCtrl)

  override def bus = io.apb
}


case class Apb3_HMAC_Std_MD5Core_Std() extends Component with ApbCryptoComponent {

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val md5Core  = new MD5Core_Std()
  val hmacCore = new HMACCore_Std(HMACCoreStdConfig(md5Core.configCore.hashBlockWidth, md5Core.configCore))

  hmacCore.io.hashCore <> md5Core.io

  val busCtrl = Apb3SlaveFactory(io.apb)
  hmacCore.io.hmacCore.driveFrom(busCtrl)

  override def bus = io.apb
}


case class Apb3_CRC_Combinational(config: CRCCombinationalConfig) extends Component with ApbCryptoComponent {

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val crc  = new CRCCombinational(config)

  val busCtrl = Apb3SlaveFactory(io.apb)
  crc.io.driveFrom(busCtrl)

  override def bus = io.apb
}




