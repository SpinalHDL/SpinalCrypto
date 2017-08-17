import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow
from cocotblib.misc import randBits, assertEquals

import hashlib
import hmac
import random
import string

###############################################################################
# MD5 Core Helper
#
class HMACCoreStdHelper:

    def __init__(self,dut):

        # IO definition -----------------------------------
        self.io = HMACCoreStdHelper.IO(dut)

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
            self.cmd.payload.fragment_key  <= 0


###############################################################################
# Ensdianess swap
def endianessWord(x):

    tmp = [x[i*2:2+i*2] for i in range(0,len(x)/2)]

    return "".join(tmp[::-1])

def endianess(x):

    tmp = [ endianessWord(x[i*8 : 8+i*8]) for i in range(0,len(x)/2)]

    return "".join(tmp)


###############################################################################
# Ensdianess swap
def endianessWord(x):

    tmp = [x[i*2:2+i*2] for i in range(0,len(x)/2)]

    return "".join(tmp[::-1])

def endianess(x):

    tmp = [ endianessWord(x[i*8 : 8+i*8]) for i in range(0,len(x)/2)]

    return "".join(tmp)


###############################################################################
# Generate a random word of a given length
def randomword(length):
    return "".join(random.choice(string.lowercase) for i in range(length))


###############################################################################
# Test HMAC - MD5
#
@cocotb.test()
def testHMACCore_MD5(dut):

    dut.log.info("Cocotb test HMAC - MD5 Core Std")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperHMAC   = HMACCoreStdHelper(dut)
    clockDomain  = ClockDomain(helperHMAC.io.clk, 200, helperHMAC.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperHMAC.io.initIO()
    yield clockDomain.event_endReset.wait()

    # start monitoring rsp
    helperHMAC.io.rsp.startMonitoringValid(helperHMAC.io.clk)
    helperHMAC.io.cmd.startMonitoringReady(helperHMAC.io.clk)


    msgPattern = [randomword(100-size) for size in range(1,100)]
    keyPattern = [randomword(30)   for _ in range(1,100)]

    #msgPattern = ["11111111222222223333333344444444555555556666666677777777"]
    #keyPattern = ["gxmlzvkwyuvtkyfhgliszczfdscqyh"]

    for index in range(0, len(msgPattern)):

        hexMsg = "".join([format(ord(c), "x") for c in msgPattern[index]])
        hexKey = "".join([format(ord(c), "x") for c in keyPattern[index]])

        print("key  : ", keyPattern[index])
        print("key  : ", hexKey)
        print("msg  : ", msgPattern[index])
        print("msg  : ", hexMsg)

        ## key padding to get a key of the size of the md5 block
        if (len(hexKey) < 128):
            hexKey = hexKey + "0" * (128 - len(hexKey))

        # Init
        yield RisingEdge(helperHMAC.io.clk)
        helperHMAC.io.init <= 1
        yield RisingEdge(helperHMAC.io.clk)
        helperHMAC.io.init <= 0
        yield RisingEdge(helperHMAC.io.clk)


        while (hexMsg != None) :

            if len(hexMsg) > 8 :
                block    = endianessWord(hexMsg[:8])
                hexMsg   = hexMsg[8:]
                isLast   = 0
                sizeLast = 0
            else:
                block    = endianessWord(hexMsg + "0" * (8 - len(hexMsg)))
                isLast   = 1
                sizeLast = (len(hexMsg)/2) - 1
                hexMsg   = None


            helperHMAC.io.cmd.valid                 <= 1
            helperHMAC.io.cmd.payload.fragment_msg  <= int(block, 16)
            helperHMAC.io.cmd.payload.fragment_key  <= int(endianess(hexKey), 16)
            helperHMAC.io.cmd.payload.fragment_size <= sizeLast
            helperHMAC.io.cmd.payload.last          <= isLast

            if isLast == 1:
                yield helperHMAC.io.rsp.event_valid.wait()
                rtlhmac = hex(int(helperHMAC.io.rsp.event_valid.data.hmac))[2:-1]
                if(len(rtlhmac) != 32):
                    rtlhmac = "0" * (32-len(rtlhmac)) + rtlhmac
            else:
                yield helperHMAC.io.cmd.event_ready.wait()


            helperHMAC.io.cmd.valid <= 0

        rtlhmac   = endianess(rtlhmac)
        print("index : ", index)

        modelHmac =  hmac.new(keyPattern[index], msgPattern[index], hashlib.md5).hexdigest()
        print("hmac : ", rtlhmac, modelHmac, int(rtlhmac, 16) == int(modelHmac, 16))
        print()

      #  assertEquals(int(rtlhmac, 16), int(modelHmac, 16), "Wrong hmac hash value computed ")


    yield Timer(50000)


