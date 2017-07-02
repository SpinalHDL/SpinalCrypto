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
            pass


###############################################################################
# Test TestBench_APB_1
#
@cocotb.test()
def testTestBench_APB_1(dut):

    helper       = TestBench_APB_Helper(dut)
    clockDomain  = ClockDomain(helper.io.clkAxi, 200, helper.io.rstAxi , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    #helperDES.io.init()
    yield clockDomain.event_endReset.wait()

    yield RisingEdge(helper.io.clkAxi)



