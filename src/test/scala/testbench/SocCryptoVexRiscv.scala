package testbench

import spinal.core._
import spinal.lib.bus.amba3.apb.{Apb3Decoder, Apb3Gpio}
import spinal.lib.bus.amba4.axi._
import spinal.lib.com.jtag.Jtag
import spinal.lib.com.uart.{Apb3UartCtrl, Uart, UartCtrlGenerics, UartCtrlMemoryMappedConfig}
import spinal.lib.io.TriStateArray
import spinal.lib.memory.sdram._
import spinal.lib.soc.pinsec.{PinsecTimerCtrl, PinsecTimerCtrlExternal}
import spinal.lib.{BufferCC, master, slave}
import vexriscv.{VexRiscv, VexRiscvConfig, plugin}
import vexriscv.ip.{DataCacheConfig, InstructionCacheConfig}
import vexriscv.plugin._


case class CryptoCPUConfig(
    axiFrequency : HertzNumber,
    onChipRamSize: BigInt,
    sdramLayout  : SdramLayout,
    sdramTimings : SdramTimings
)

object CryptoCPUConfig{
  def de1_soc = CryptoCPUConfig(
      axiFrequency   = 50 MHz,
      onChipRamSize  = 4 kB,
      sdramLayout    = IS42x320D.layout,
      sdramTimings   = IS42x320D.timingGrade7
  )
}

object CryptoVexRiscvConfig{

  def config(axiClockDomain: ClockDomain) = VexRiscvConfig(
    plugins = List(
      new PcManagerSimplePlugin(0x00000000l, false),
      new IBusCachedPlugin(
        config = InstructionCacheConfig(
          cacheSize = 4096,
          bytePerLine =32,
          wayCount = 1,
          wrappedMemAccess = true,
          addressWidth = 32,
          cpuDataWidth = 32,
          memDataWidth = 32,
          catchIllegalAccess = true,
          catchAccessFault = true,
          catchMemoryTranslationMiss = true,
          asyncTagMemory = false,
          twoStageLogic = true
        )
      ),
      new DBusCachedPlugin(
        config = new DataCacheConfig(
          cacheSize         = 4096,
          bytePerLine       = 32,
          wayCount          = 1,
          addressWidth      = 32,
          cpuDataWidth      = 32,
          memDataWidth      = 32,
          catchAccessError  = true,
          catchIllegal      = true,
          catchUnaligned    = true,
          catchMemoryTranslationMiss = true
        ),
        memoryTranslatorPortConfig = null
      ),
      new StaticMemoryTranslatorPlugin(
        ioRange      = _(31 downto 28) === 0xF
      ),
      new DecoderSimplePlugin(
        catchIllegalInstruction = true
      ),
      new RegFilePlugin(
        regFileReadyKind = plugin.SYNC,
        zeroBoot = false
      ),
      new IntAluPlugin,
      new SrcPlugin(
        separatedAddSub = false,
        executeInsertion = true
      ),
      new FullBarrielShifterPlugin,
      new MulPlugin,
      new DivPlugin,
      new HazardSimplePlugin(
        bypassExecute           = true,
        bypassMemory            = true,
        bypassWriteBack         = true,
        bypassWriteBackBuffer   = true,
        pessimisticUseSrc       = false,
        pessimisticWriteRegFile = false,
        pessimisticAddressMatch = false
      ),
      new DebugPlugin(axiClockDomain),
      new BranchPlugin(
        earlyBranch = false,
        catchAddressMisaligned = true,
        prediction = STATIC
      ),
      new CsrPlugin(
        config = CsrPluginConfig(
          catchIllegalAccess = false,
          mvendorid      = null,
          marchid        = null,
          mimpid         = null,
          mhartid        = null,
          misaExtensionsInit = 66,
          misaAccess     = CsrAccess.NONE,
          mtvecAccess    = CsrAccess.NONE,
          mtvecInit      = 0x00000020l,
          mepcAccess     = CsrAccess.READ_WRITE,
          mscratchGen    = false,
          mcauseAccess   = CsrAccess.READ_ONLY,
          mbadaddrAccess = CsrAccess.READ_ONLY,
          mcycleAccess   = CsrAccess.NONE,
          minstretAccess = CsrAccess.NONE,
          ecallGen       = false,
          wfiGen         = false,
          ucycleAccess   = CsrAccess.NONE
        )
      ),
      new YamlPlugin("cpu0.yaml")
    )
  )
}





class SocCryptoVexRiscv(config: CryptoCPUConfig) extends Component{

  import config._
  val debug = true
  val interruptCount = 4

  val io = new Bundle{

    //Clocks / reset
    val asyncReset = in Bool
    val axiClk     = in Bool

    //Main components IO
    val jtag       = slave(Jtag())
    val sdram      = master(SdramInterface(sdramLayout))

    //Peripherals IO
    val gpioA         = master(TriStateArray(32 bits))
    val uart          = master(Uart())

    val timerExternal = in(PinsecTimerCtrlExternal())
    val coreInterrupt = in Bool
  }

  val resetCtrlClockDomain = ClockDomain(
    clock = io.axiClk,
    config = ClockDomainConfig(
      resetKind = BOOT
    )
  )

  val resetCtrl = new ClockingArea(resetCtrlClockDomain) {
    val axiResetUnbuffered  = False
    val coreResetUnbuffered = False

    //Implement an counter to keep the reset axiResetOrder high 64 cycles
    // Also this counter will automaticly do a reset when the system boot.
    val axiResetCounter = Reg(UInt(6 bits)) init(0)
    when(axiResetCounter =/= U(axiResetCounter.range -> true)){
      axiResetCounter := axiResetCounter + 1
      axiResetUnbuffered := True
    }
    when(BufferCC(io.asyncReset)){
      axiResetCounter := 0
    }

    //When an axiResetOrder happen, the core reset will as well
    when(axiResetUnbuffered){
      coreResetUnbuffered := True
    }

    //Create all reset used later in the design
    val axiReset  = RegNext(axiResetUnbuffered)
    val coreReset = RegNext(coreResetUnbuffered)
  }

  val axiClockDomain = ClockDomain(
    clock = io.axiClk,
    reset = resetCtrl.axiReset,
    frequency = FixedFrequency(axiFrequency) //The frequency information is used by the SDRAM controller
  )

  val coreClockDomain = ClockDomain(
    clock = io.axiClk,
    reset = resetCtrl.coreReset
  )


  val axi = new ClockingArea(axiClockDomain) {
    val ram = Axi4SharedOnChipRam(
      dataWidth = 32,
      byteCount = onChipRamSize,
      idWidth = 4
    )

    val sdramCtrl = Axi4SharedSdramCtrl(
      axiDataWidth = 32,
      axiIdWidth   = 4,
      layout       = sdramLayout,
      timing       = sdramTimings,
      CAS          = 3
    )


    val apbBridge = Axi4SharedToApb3Bridge(
      addressWidth = 20,
      dataWidth    = 32,
      idWidth      = 4
    )

    val gpioACtrl = Apb3Gpio(
      gpioWidth = 32
    )

    val timerCtrl = PinsecTimerCtrl()

    val uartCtrlConfig = UartCtrlMemoryMappedConfig(
      uartCtrlConfig = UartCtrlGenerics(
        dataWidthMax      = 8,
        clockDividerWidth = 20,
        preSamplingSize   = 1,
        samplingSize      = 5,
        postSamplingSize  = 2
      ),
      txFifoDepth = 16,
      rxFifoDepth = 16
    )
    val uartCtrl = Apb3UartCtrl(uartCtrlConfig)



    val core = new ClockingArea(coreClockDomain){

      val cpu = new VexRiscv(CryptoVexRiscvConfig.config(axiClockDomain))
      var iBus : Axi4ReadOnly = null
      var dBus : Axi4Shared = null
      var debugBus : DebugExtensionBus = null
      for(plugin <- cpu.config.plugins) plugin match{
        case plugin : IBusSimplePlugin => iBus = plugin.iBus.toAxi4ReadOnly()
        case plugin : IBusCachedPlugin => iBus = plugin.iBus.toAxi4ReadOnly()
        case plugin : DBusSimplePlugin => dBus = plugin.dBus.toAxi4Shared()
        case plugin : DBusCachedPlugin => dBus = plugin.dBus.toAxi4Shared(true)
        case plugin : CsrPlugin        => {
          plugin.externalInterrupt := BufferCC(io.coreInterrupt)
          plugin.timerInterrupt := timerCtrl.io.interrupt
        }
        case plugin : DebugPlugin      => {
          resetCtrl.coreResetUnbuffered setWhen(plugin.io.resetOut)
          debugBus = plugin.io.bus
        }
        case _ =>
      }
    }


    val axiCrossbar = Axi4CrossbarFactory()

    axiCrossbar.addSlaves(
      ram.io.axi       -> (0x00000000L,   onChipRamSize),
      sdramCtrl.io.axi -> (0x40000000L,   sdramLayout.capacity),
      apbBridge.io.axi -> (0xF0000000L,   1 MB)
    )

    axiCrossbar.addConnections(
      core.iBus       -> List(ram.io.axi, sdramCtrl.io.axi),
      core.dBus       -> List(ram.io.axi, sdramCtrl.io.axi, apbBridge.io.axi)
    )


    axiCrossbar.addPipelining(apbBridge.io.axi)((crossbar,bridge) => {
      crossbar.sharedCmd.halfPipe() >> bridge.sharedCmd
      crossbar.writeData.halfPipe() >> bridge.writeData
      crossbar.writeRsp             << bridge.writeRsp
      crossbar.readRsp              << bridge.readRsp
    })

    axiCrossbar.addPipelining(sdramCtrl.io.axi)((crossbar,ctrl) => {
      crossbar.sharedCmd.halfPipe()  >>  ctrl.sharedCmd
      crossbar.writeData            >/-> ctrl.writeData
      crossbar.writeRsp              <<  ctrl.writeRsp
      crossbar.readRsp               <<  ctrl.readRsp
    })

    axiCrossbar.addPipelining(ram.io.axi)((crossbar,ctrl) => {
      crossbar.sharedCmd.halfPipe()  >>  ctrl.sharedCmd
      crossbar.writeData            >/-> ctrl.writeData
      crossbar.writeRsp              <<  ctrl.writeRsp
      crossbar.readRsp               <<  ctrl.readRsp
    })


    axiCrossbar.addPipelining(core.dBus)((cpu,crossbar) => {
      cpu.sharedCmd             >>  crossbar.sharedCmd
      cpu.writeData             >>  crossbar.writeData
      cpu.writeRsp              <<  crossbar.writeRsp
      cpu.readRsp               <-< crossbar.readRsp
    })

    axiCrossbar.build()



    val desCore       = Apb3_DESCore()
    val tripleDESCore = APB3_3DESCore()
    val md5Core       = APB3_MD5()
    val hmacMD5       = APB3_HMAC_MD5()



    val apbDecoder = Apb3Decoder(
      master = apbBridge.io.apb,
      slaves = List(
        gpioACtrl.io.apb     -> (0x0000, 1 kB),
        uartCtrl.io.apb      -> (0x1000, 1 kB),
        timerCtrl.io.apb     -> (0x2000, 1 kB),
        desCore.io.apb       -> (0x3000, 1 kB),
        tripleDESCore.io.apb -> (0x4000, 1 kB),
        hmacMD5.io.apb       -> (0x5000, 1 kB),
        md5Core.io.apb       -> (0x6000, 1 kB)
      )
    )

    io.jtag <> core.debugBus.fromJtag()
  }

  io.gpioA          <> axi.gpioACtrl.io.gpio
  io.timerExternal  <> axi.timerCtrl.io.external
  io.uart           <> axi.uartCtrl.io.uart
  io.sdram          <> axi.sdramCtrl.io.sdram
}

//DE1-SoC
object CryptoSoc{
  def main(args: Array[String]) {
    val config = SpinalConfig()
    config.generateVerilog({
      val toplevel = new SocCryptoVexRiscv(CryptoCPUConfig.de1_soc)
      toplevel
    })
  }
}