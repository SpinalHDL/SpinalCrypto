import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow
from cocotblib.misc import randBits, assertEquals


###############################################################################
# MD5 Core Helper
#
class MD5EngineStdHelper:

    def __init__(self,dut):

        # IO definition -----------------------------------
        self.io = MD5EngineStdHelper.IO(dut)

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

        def initIO(self):
            self.cmd.valid         <= 0
            self.cmd.payload.block <= 0
            self.init              <= 0


###############################################################################
# Test MD5 Engine
#
@cocotb.test()
def testMD5EngineStd(dut):

    dut.log.info("Cocotb test MD5 Engine Std")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperMD5    = MD5EngineStdHelper(dut)
    clockDomain  = ClockDomain(helperMD5.io.clk, 200, helperMD5.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperMD5.io.initIO()
    yield clockDomain.event_endReset.wait()

    # start monitoring rsp
    helperMD5.io.rsp.startMonitoringValid(helperMD5.io.clk)



    # Fix patterns
    msgs  = [[0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000],

              [0x00000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000],

              [0x80636261000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001800000000],

              [0x34333231383736353231303936353433303938373433323138373635323130393635343330393837343332313837363532313039363534333039383734333231,
               0x38373635323130393635343330393837000000800000000000000000000000000000000000000000000000000000000000000000000000000000028000000000]
              ]

    digests = [0x031F1DAC6EA58ED01FAB67B774317791,
               0xD98C1DD404B2008F980980E97E42F8EC,
               0x98500190B04FD23C7D3F96D6727FE128,
               0xA2F4ED5755C9E32B2EDA49AC7AB60721]

    # Process all pattern
    indexPattern = 0
    for msgPattern in msgs:

        # Init MD5
        yield RisingEdge(helperMD5.io.clk)
        helperMD5.io.init <= 1
        yield RisingEdge(helperMD5.io.clk)
        helperMD5.io.init <= 0
        yield RisingEdge(helperMD5.io.clk)


        for msgBlock in msgPattern:

            # Hash data
            helperMD5.io.cmd.valid          <= 1
            helperMD5.io.cmd.payload.block  <= msgBlock

            # wait the end of the encryption
            yield helperMD5.io.rsp.event_valid.wait()

            helperMD5.io.cmd.valid <= 0

            rtlDigest = "{0:0>4X}".format(int(str(helperMD5.io.rsp.payload.hash), 2))

            yield RisingEdge(helperMD5.io.clk)

        assertEquals(int(rtlDigest, 16) , digests[indexPattern], "Wrong digest")

        yield RisingEdge(helperMD5.io.clk)

        yield Timer(50000)

        indexPattern += 1
