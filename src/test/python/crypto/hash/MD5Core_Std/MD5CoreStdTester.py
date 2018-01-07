import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow
from cocotblib.misc import randBits, assertEquals

import hashlib
import random
import string

###############################################################################
# MD5 Core Helper
#
class MD5CoreStdHelper:

    def __init__(self,dut):

        # IO definition -----------------------------------
        self.io = MD5CoreStdHelper.IO(dut)

    #==========================================================================
    # Rename IO
    #==========================================================================
    class IO:

        def __init__ (self, dut):
            self.init   = dut.io_init
            self.cmd    = Stream(dut, "io_cmd")
            self.rsp    = Flow(dut, "io_rsp")
            self.clk    = dut.clk
            self.resetn = dut.resetn


        def initIO(self):
            self.cmd.valid                 <= 0
            self.cmd.payload.last          <= 0
            self.cmd.payload.fragment_msg  <= 0
            self.cmd.payload.fragment_size <= 0


###############################################################################
# Ensdianess swap
def endianessWord(x):

    tmp = [x[i*2:2+i*2] for i in range(0,len(x)/2)]

    return "".join(tmp[::-1])

def endianess(x):

    tmp = [ endianessWord(x[i*8 : 8+i*8]) for i in range(0,len(x)/2)]
    2
    return "".join(tmp)

###############################################################################
# Generate a random word of a given length
def randomword(length):
    return "".join(random.choice(string.lowercase) for i in range(length))


###############################################################################
# Test MD5 Core
#
@cocotb.test()
def testMD5CoreStd(dut):

    dut.log.info("Cocotb test MD5 Core Std")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperMD5    = MD5CoreStdHelper(dut)
    clockDomain  = ClockDomain(helperMD5.io.clk, 200, helperMD5.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperMD5.io.initIO()
    yield clockDomain.event_endReset.wait()

    # start monitoring rsp
    helperMD5.io.rsp.startMonitoringValid(helperMD5.io.clk)
    helperMD5.io.cmd.startMonitoringReady(helperMD5.io.clk)


    # Fix patterns
    #
    msgPattern = [randomword(100-size) for size in range(1,100)]
    #msgPattern = ["11111111222222223333333344444444555555556666666677777777"]

    for tmpMsg in msgPattern:

        hexMsg = "".join([format(ord(c), "x") for c in tmpMsg])

        # Init MD5
        yield RisingEdge(helperMD5.io.clk)
        helperMD5.io.init <= 1
        yield RisingEdge(helperMD5.io.clk)
        helperMD5.io.init <= 0
        yield RisingEdge(helperMD5.io.clk)

        block = 0
        rtlHash = 0

        while (hexMsg != None) :

            isLast   = 0
            sizeLast = 0

            if len(hexMsg) > 8 :
                block  = endianessWord(hexMsg[:8])
                hexMsg = hexMsg[8:]
                isLast = 0
            else:
                block    = endianessWord(hexMsg + "0" * (8 - len(hexMsg)))
                isLast   = 1
                sizeLast = (len(hexMsg)/2) - 1
                hexMsg   = None

            helperMD5.io.cmd.valid                 <= 1
            helperMD5.io.cmd.payload.fragment_msg  <= int(block, 16)
            helperMD5.io.cmd.payload.fragment_size <= sizeLast
            helperMD5.io.cmd.payload.last          <= isLast

            if isLast == 1:
                yield helperMD5.io.rsp.event_valid.wait()
                tmp = hex(int(helperMD5.io.rsp.event_valid.data.digest))[2:-1]
                if(len(tmp) != 32):
                    tmp = "0" * (32-len(tmp)) + tmp
            else:
                yield helperMD5.io.cmd.event_ready.wait()

            helperMD5.io.cmd.valid                <= 0

            yield RisingEdge(helperMD5.io.clk)

        rtlHash = endianess(tmp)

        # Check result
        m = hashlib.md5(tmpMsg)
        modelHash = m.hexdigest()


        assertEquals(int(rtlHash,16), int(modelHash, 16), "Wrong MD5 hash value computed ")

        print("hash-model: ", int(rtlHash, 16) == int(modelHash, 16)  , " :" , rtlHash, " - ", modelHash , " -- : ", tmpMsg)

        yield Timer(50000)


