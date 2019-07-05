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
    sdramTimings : SdramTimings,
    enableUart   : Boolean,
    enableGPIO   : Boolean,
    nbrGPIO      : Int
)

object CryptoCPUConfig{
  def de1_soc = CryptoCPUConfig(
      axiFrequency   = 50 MHz,
      onChipRamSize  = 4 kB,
      sdramLayout    = IS42x320D.layout,
      sdramTimings   = IS42x320D.timingGrade7,
      enableUart     = true,
      enableGPIO     = true,
      nbrGPIO        = 2
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
  //        wrappedMemAccess = true,
          addressWidth = 32,
          cpuDataWidth = 32,
          memDataWidth = 32,
          catchIllegalAccess = true,
          catchAccessFault = true,
          asyncTagMemory = false
//          twoStageLogic = true
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
          catchUnaligned    = true
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
   //   new FullBarrielShifterPlugin,
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
        catchAddressMisaligned = true
      ),
      new CsrPlugin(
        config = CsrPluginConfig.small(0x00000020l)
      ),
      new YamlPlugin("cpu0.yaml")
    )
  )
}





class SocCryptoVexRiscv(config: CryptoCPUConfig)(apbSlaves: (() => ApbCryptoComponent)*) extends Component {

  import config._
  val debug = true
  val interruptCount = 4

  val io = new Bundle {

    //Clocks / reset
    val asyncReset = in Bool
    val axiClk     = in Bool

    //Main components IO
    val jtag       = slave(Jtag())
    val sdram      = master(SdramInterface(sdramLayout))

    //Peripherals IO
    val gpioA         = if(config.enableGPIO) master(TriStateArray(32 bits)) else null
    val uart          = if(config.enableUart) master(Uart()) else null

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
    // Also this counter will automaticaly do a reset when the system boot.
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


    val apbBridge = new AxiShared2Apb_TB(AxiShared2Apb_TB.defaultConfig.copy(enableUART = enableUart))(apbSlaves:_*)

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
          plugin.timerInterrupt := False// timerCtrl.io.interrupt
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
      ram.io.axi             -> (0x80000000L,   onChipRamSize),
      sdramCtrl.io.axi       -> (0x40000000L,   sdramLayout.capacity),
      apbBridge.io.axiShared -> (0xF0000000L,   1 MB)
    )

    axiCrossbar.addConnections(
      core.iBus       -> List(ram.io.axi, sdramCtrl.io.axi),
      core.dBus       -> List(ram.io.axi, sdramCtrl.io.axi, apbBridge.io.axiShared)
    )


    axiCrossbar.addPipelining(apbBridge.io.axiShared)((crossbar,bridge) => {
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

    io.jtag <> core.debugBus.fromJtag()
  }

  if(config.enableGPIO) io.gpioA <>  axi.apbBridge.io.gpioA

  if(config.enableUart) io.uart <> axi.apbBridge.io.uart

  io.sdram <> axi.sdramCtrl.io.sdram
}

