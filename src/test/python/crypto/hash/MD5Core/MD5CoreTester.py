import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow


###############################################################################
# MD5 Core Helper
#
class MD5CoreHelper:

    def __init__(self,dut):

        # IO definition -----------------------------------
        self.io = MD5CoreHelper.IO(dut)

    #==========================================================================
    # Rename IO
    #==========================================================================
    class IO:

        def __init__ (self, dut):
            self.cmd    = Stream(dut, "io_cmd")
            self.rsp    = Flow(dut, "io_rsp")
            self.init   = dut.io_init
            self.clk    = dut.clk
            self.resetn = dut.resetn

        def init(self):
            self.cmd.valid          <= 0
            self.cmd.payload.block  <= 0



###############################################################################
# Test MD5 Core
#
@cocotb.test()
def testMD5Core(dut):

    dut.log.info("Cocotb test MD5 Core")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperMD5    = MD5CoreHelper(dut)
    clockDomain  = ClockDomain(helperMD5.io.clk, 200, helperMD5.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    #helperMD5.io.init()
    helperMD5.io.cmd.valid          <= 0
    helperMD5.io.cmd.payload.block  <= 0
    yield clockDomain.event_endReset.wait()

    # start monitoring rsp
    helperMD5.io.rsp.startMonitoringValid(helperMD5.io.clk)


    # Init MD5
    helperMD5.io.init <= 1
    yield RisingEdge(helperMD5.io.clk)
    helperMD5.io.init <= 0
    yield RisingEdge(helperMD5.io.clk)

    # Vector test ...
    data  = [0x123456ABCD132536AABBCCDD11223344,
             0x800000000000000000000000000000AA]

    # Hash data
    helperMD5.io.cmd.valid          <= 1
    helperMD5.io.cmd.payload.block  <= data[0]

    # wait the end of the encryption
    yield helperMD5.io.rsp.event_valid.wait()

    helperMD5.io.cmd.valid <= 0


    yield RisingEdge(helperMD5.io.clk)
    yield Timer(100000)






