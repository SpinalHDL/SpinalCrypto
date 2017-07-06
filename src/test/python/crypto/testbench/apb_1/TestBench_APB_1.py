import binascii

import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge
from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow
from cocotblib.Axi4 import Axi4
from cocotblib.TriState import TriState
from cocotblib.misc import randBits, assertEquals



###############################################################################
# TestBench APB Helper
#
class TestBench_APB_Helper:

    def __init__(self,dut):

        # IO definition -----------------------------------
        self.io = TestBench_APB_Helper.IO(dut)

    #==========================================================================
    # Rename IO
    #==========================================================================
    class IO:

        def __init__ (self, dut):
            self.axi    = Axi4(dut, "io_axi")
            self.gpioA  = TriState(dut, "io_gpioA")
            self.clkAxi = dut.io_axiClk
            self.rstAxi = dut.io_axiRstn


        def init(self):
            self.axi.aw.valid         <= 0
            self.axi.aw.payload.addr  <= 0
            self.axi.aw.payload.hid   <= 0
            self.axi.aw.payload.len   <= 0
            self.axi.aw.payload.size  <= 0
            self.axi.aw.payload.burst <= 0

            self.axi.ar.valid         <= 0
            self.axi.ar.payload.addr  <= 0
            self.axi.ar.payload.hid   <= 0
            self.axi.ar.payload.len   <= 0
            self.axi.ar.payload.size  <= 0
            self.axi.ar.payload.burst <= 0

            self.axi.w.valid        <= 0
            self.axi.w.payload.data <= 0
            self.axi.w.payload.strb <= 0
            self.axi.w.payload.last <= 0

            self.axi.b.ready <= 0

            self.axi.r.ready <= 0


@cocotb.coroutine
def axiSendBurst(axi, clk, address, datas):

    addrCnt = address

    for data in datas:
        axi.aw.valid         <= 1
        axi.aw.payload.addr  <= addrCnt
        axi.aw.payload.hid   <= 1
        axi.aw.payload.len   <= 0
        axi.aw.payload.size  <= 5 # 32-bit of data
        axi.aw.payload.burst <= 1 # incr

        yield RisingEdge(clk)

        axi.w.valid        <= 1
        axi.w.payload.data <= data
        axi.w.payload.strb <= 4
        axi.w.payload.last <= 0

        yield axi.w.event_ready.wait()

        axi.w.valid <=  0
        axi.aw.valid <= 0

        yield RisingEdge(clk)

        axi.b.ready <= 1

        yield RisingEdge(clk)

        addrCnt = addrCnt + 4



@cocotb.coroutine
def axiSend(axi, clk, address, data):

    axi.aw.valid         <= 1
    axi.aw.payload.addr  <= address
    axi.aw.payload.hid   <= 1
    axi.aw.payload.len   <= 0
    axi.aw.payload.size  <= 5 # 32-bit of data
    axi.aw.payload.burst <= 1 # incr

    yield RisingEdge(clk)

    axi.w.valid        <= 1
    axi.w.payload.data <= data
    axi.w.payload.strb <= 4
    axi.w.payload.last <= 0

    yield axi.w.event_ready.wait()

    axi.w.valid <=  0
    axi.aw.valid <= 0

    yield RisingEdge(clk)

    axi.b.ready <= 1

    yield RisingEdge(clk)

    #axi.b.ready <= 0


@cocotb.coroutine
def axiRead(axi, clk, address):

    axi.ar.valid         <= 1
    axi.ar.payload.addr  <= address
    axi.aw.payload.hid   <= 2
    axi.ar.payload.len   <= 0
    axi.ar.payload.size  <= 5 # 32-bit of data
    axi.ar.payload.burst <= 1 # incr

    yield axi.ar.event_ready.wait()
    axi.ar.valid <= 0
    axi.r.ready <= 1

    yield axi.r.event_valid.wait()

    axi.r.ready <= 0

    yield RisingEdge(clk)


##
## TODO : manage the axi.b.ready singal !!!!!
##


###############################################################################
# Test TestBench_APB_1 DES
#
@cocotb.test()
def testTestBench_APB_1_DES(dut):

    dut.log.info("Cocotb TestBench APB DES")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helper       = TestBench_APB_Helper(dut)
    clockDomain  = ClockDomain(helper.io.clkAxi, 200, helper.io.rstAxi , RESET_ACTIVE_LEVEL.LOW)


    helper.io.axi.w.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.ar.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.r.startMonitoringValid(helper.io.clkAxi)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helper.io.init()
    yield clockDomain.event_endReset.wait()


    # DES - Write in parameter
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x1000, 0x11111111)  # DES - key_lsb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x1004, 0x22222222)  # DES - key_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x1008, 0xAAAAAAAA)  # DES - block_lsb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x100C, 0xBBBBBBBB)  # DES - block_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x1010, 0x00000001)  # DES - enc/dec
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x1014, 0x00000001)  # DES - valid

    # DES - Polling
    status = 0
    while status == 0:

        yield axiRead(helper.io.axi, helper.io.clkAxi, 0x1018)
        status = int(helper.io.axi.r.event_valid.data.data)


    # DES - Read output parameter
    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x101C)
    cipher_lsb = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x1020)
    cipher_msb = int(helper.io.axi.r.event_valid.data.data)

    cipher = (cipher_msb << 32) + cipher_lsb
    print("data des ", hex(cipher))


    yield RisingEdge(helper.io.clkAxi)

    yield Timer(10000)


###############################################################################
# Test TestBench_APB_1 3DES
#
@cocotb.test()
def testTestBench_APB_1_3DES(dut):

    dut.log.info("Cocotb TestBench APB 3DES")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helper       = TestBench_APB_Helper(dut)
    clockDomain  = ClockDomain(helper.io.clkAxi, 200, helper.io.rstAxi , RESET_ACTIVE_LEVEL.LOW)


    helper.io.axi.w.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.ar.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.r.startMonitoringValid(helper.io.clkAxi)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helper.io.init()
    yield clockDomain.event_endReset.wait()


    # 3DES - Write in parameter
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2000, 0x11111111)  # 3DES - key_lsb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2004, 0x22222222)  # 3DES - key_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2008, 0x33333333)  # 3DES - key_lsb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x200C, 0x44444444)  # 3DES - key_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2010, 0x55555555)  # 3DES - key_lsb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2014, 0x66666666)  # 3DES - key_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2018, 0xAAAAAAAA)  # 3DES - block_lsb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x201C, 0xBBBBBBBB)  # 3DES - block_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2020, 0x00000001)  # 3DES - enc/dec
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x2024, 0x00000001)  # 3DES - valid

    # 3DES - Polling
    status = 0
    while status == 0:

        yield axiRead(helper.io.axi, helper.io.clkAxi, 0x2028)
        status = int(helper.io.axi.r.event_valid.data.data)


    # 3DES - Read output parameter
    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x202C)
    cipher_lsb = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x2030)
    cipher_msb = int(helper.io.axi.r.event_valid.data.data)

    cipher = (cipher_msb << 32) + cipher_lsb
    print("data 3des ", hex(cipher))


    yield RisingEdge(helper.io.clkAxi)

    yield Timer(10000)



###############################################################################
# Test TestBench_APB_1 HMAC MD5
#
@cocotb.test()
def testTestBench_APB_1_HMAC_MD5(dut):

    dut.log.info("Cocotb TestBench APB HMAC MD5")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helper       = TestBench_APB_Helper(dut)
    clockDomain  = ClockDomain(helper.io.clkAxi, 200, helper.io.rstAxi , RESET_ACTIVE_LEVEL.LOW)


    helper.io.axi.w.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.ar.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.r.startMonitoringValid(helper.io.clkAxi)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helper.io.init()
    yield clockDomain.event_endReset.wait()


    # HMAC - Write in parameter
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x304C, 0x00000001)  # HMAC - init
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x3000, 0x11111111)  # HMAC - msg
    yield axiSendBurst(helper.io.axi, helper.io.clkAxi, 0x3004, [0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD,0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD,0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD,0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD, 0xAABBCCDD])# HMAC - key_msb
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x3044, 0x00000001)  # HMAC - last
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x3048, 0x00000003)  # HMAC - Size
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x3050, 0x00000001)  # HMAC - valid


    # HMAC - Polling
    status = 0
    while status == 0:

        yield axiRead(helper.io.axi, helper.io.clkAxi, 0x3054)
        status = int(helper.io.axi.r.event_valid.data.data)


    # HMAC - Read output parameter
    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x3058)
    cipher_1 = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x305C)
    cipher_2 = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x3060)
    cipher_3 = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x3064)
    cipher_4 = int(helper.io.axi.r.event_valid.data.data)

    cipher = (cipher_1 << 96) + (cipher_2 << 64) + (cipher_3 << 32) + cipher_4
    print("data HMAC MD5 ", hex(cipher))


    yield RisingEdge(helper.io.clkAxi)

    yield Timer(10000)


###############################################################################
# Test TestBench_APB_1 MD5
#
@cocotb.test()
def testTestBench_APB_1_MD5(dut):

    dut.log.info("Cocotb TestBench APB MD5")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helper       = TestBench_APB_Helper(dut)
    clockDomain  = ClockDomain(helper.io.clkAxi, 200, helper.io.rstAxi , RESET_ACTIVE_LEVEL.LOW)


    helper.io.axi.w.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.ar.startMonitoringReady(helper.io.clkAxi)
    helper.io.axi.r.startMonitoringValid(helper.io.clkAxi)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helper.io.init()
    yield clockDomain.event_endReset.wait()


    # MD5 - Write in parameter
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x400C, 0x00000001)  # HMAC - init
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x4000, 0x11111111)  # HMAC - msg
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x4004, 0x00000003)  # HMAC - size
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x4008, 0x00000001)  # HMAC - last
    yield axiSend(helper.io.axi, helper.io.clkAxi, 0x4010, 0x00000001)  # HMAC - valid


    # MD5 - Polling
    status = 0
    while status == 0:

        yield axiRead(helper.io.axi, helper.io.clkAxi, 0x4014)
        status = int(helper.io.axi.r.event_valid.data.data)


    # MD5 - Read output parameter
    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x4018)
    cipher_1 = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x401C)
    cipher_2 = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x4020)
    cipher_3 = int(helper.io.axi.r.event_valid.data.data)

    yield axiRead(helper.io.axi, helper.io.clkAxi, 0x4024)
    cipher_4 = int(helper.io.axi.r.event_valid.data.data)

    cipher = (cipher_1 << 96) + (cipher_2 << 64) + (cipher_3 << 32) + cipher_4
    print("data MD5 ", hex(cipher))


    yield RisingEdge(helper.io.clkAxi)

    yield Timer(10000)