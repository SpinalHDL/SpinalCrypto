package play

import spinal.core._
import spinal.lib._
import spinal.lib.bus.amba3.apb.{Apb3, Apb3Decoder, Apb3Gpio, Apb3SlaveFactory}
import spinal.lib.bus.amba4.axi._
import spinal.lib.com.uart.Apb3UartCtrl
import spinal.lib.io.TriStateArray
import spinalcrypto.symmetric.SymmetricCryptoCoreIO
import spinalcrypto.symmetric.des._



case class Apb3DESCore() extends Component{

  val desCore = new DESCore_Std()

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3UartCtrl.getApb3Config))
    val core      = slave(SymmetricCryptoCoreIO(desCore.gIO))
  }

  val busCtrl = Apb3SlaveFactory(io.apb)

  //
}

/*

object Axi4ToAxi4Shared{
  def apply(axi : Axi4): Axi4Shared ={
    val axiShared = new Axi4Shared(axi.config)
    val arbiter = StreamArbiterFactory.roundRobin.build(new Axi4Ax(axi.config),2)
    arbiter.io.inputs(0) << axi.ar.asInstanceOf[Stream[Axi4Ax]]
    arbiter.io.inputs(1) << axi.aw.asInstanceOf[Stream[Axi4Ax]]

    axiShared.arw.arbitrationFrom(arbiter.io.output)
    axiShared.arw.payload.assignSomeByName(arbiter.io.output.payload)
    axiShared.arw.write := arbiter.io.chosenOH(1)
    axi.w >> axiShared.w
    axi.b << axiShared.b
    axi.r << axiShared.r
    axiShared
  }

  def main(args: Array[String]) {
    SpinalVhdl(new Component{
      val axi = slave(Axi4(Axi4Config(32,32,2)))
      val axiShared = master(Axi4ToAxi4Shared(axi))
    })
  }
}

*/



class TestBench extends Component{

  val axi4Config = Axi4Config(addressWidth = 32,
                              dataWidth    = 32,
                              idWidth      = 2,
                              useId        = true,
                              useRegion    = false,
                              useBurst     = true,
                              useLock      = false,
                              useCache     = false,
                              useSize      = true,
                              useQos       = false,
                              useLen       = true,
                              useLast      = true,
                              useResp      = true,
                              useProt      = false,
                              useStrb      = true,
                              useUser      = false,
                              userWidth    = -1)

  val io = new Bundle{
    val axiClk    = in Bool
    val axiRstn   = in Bool

    val axi       = slave(Axi4(axi4Config))

    val gpioA     = master(TriStateArray(32 bits))
  }


  val axiClockDomain = ClockDomain(
    clock = io.axiClk,
    reset = io.axiRstn
  )


  val axi = new ClockingArea(axiClockDomain) {


    println(log2Up(1))

    val apbBridge = Axi4SharedToApb3Bridge(
      addressWidth = 32,
      dataWidth    = 32,
      idWidth      = 2
    )

    val gpioACtrl = Apb3Gpio(
      gpioWidth = 32
    )

   // val desCore = new DESCore_Std()


    val axiArbitrer = new Axi4SharedArbiter(
      outputConfig      = axi4Config,
      readInputsCount   = 1,
      writeInputsCount  = 1,
      sharedInputsCount = 0,
      routeBufferSize   = 2)

    axiArbitrer.io.readInputs(0)  <> io.axi.toReadOnly()
    axiArbitrer.io.writeInputs(0) <> io.axi.toWriteOnly()
    apbBridge.io.axi <> axiArbitrer.io.output

    val apbDecoder = Apb3Decoder(
      master = apbBridge.io.apb,
      slaves = List(
        gpioACtrl.io.apb -> (0x00000, 4 kB)
      )
    )

  }

  io.gpioA  <> axi.gpioACtrl.io.gpio
}


object PlayWithTestBench{
  def main(args: Array[String]): Unit = {
    SpinalVhdl(new TestBench)
  }
}
