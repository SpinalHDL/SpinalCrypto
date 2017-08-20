import binascii

import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge
from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow
from cocotblib.misc import randBits, assertEquals

from crypto.symmetric.pyaes.aes import *




###############################################################################
# AES Block Helper
#
class AESCoreStdHelper:

    def __init__(self,dut):

        # IO definition -----------------------------------
        self.io = AESCoreStdHelper.IO(dut)

    #==========================================================================
    # Rename IO
    #==========================================================================
    class IO:

        def __init__ (self, dut):
            self.cmd    = Stream(dut, "io_cmd")
            self.rsp    = Flow(dut, "io_rsp")
            self.clk    = dut.clk
            self.resetn = dut.resetn

        def init(self):
            self.cmd.valid          <= 0
            self.cmd.payload.block  <= 0
            self.cmd.payload.key    <= 0
            self.cmd.payload.enc    <= 0




###############################################################################
# Test AES Core
#
@cocotb.test()
def testAESCore128_Std(dut):
    print("Test pyaes")

    key = "This_key_for_demo_purposes_only!" # 256 bits

    aes        = AESModeOfOperationECB(key)
    plaintext  = "TextMustBe16Byte"
    ciphertext = aes.encrypt(plaintext)

    # 'L6\x95\x85\xe4\xd9\xf1\x8a\xfb\xe5\x94X\x80|\x19\xc3'
    print(repr(ciphertext))
    print("ciphertext", ciphertext)
    print(binascii.hexlify(ciphertext))

    # Since there is no state stored in this mode of operation, it
    # is not necessary to create a new aes object for decryption.
    #aes = pyaes.AESModeOfOperationECB(key)
    decrypted = aes.decrypt(ciphertext)

    # True
    print("decrypted ",  decrypted)
    print decrypted == plaintext


    #########
    dut.log.info("Cocotb test AES Core")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperAES    = AESCoreStdHelper(dut)
    clockDomain  = ClockDomain(helperAES.io.clk, 200, helperAES.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperAES.io.init()
    yield clockDomain.event_endReset.wait()

    # start monitoring the Valid signal
    helperAES.io.rsp.startMonitoringValid(helperAES.io.clk)


    # Vector test ...
    key  = 0x00000000000000000000000000000000
    data = 0x0000000000000000
    data = 0x3243f6a8885a308d313198a2e0370734
    key  = 0x2B7E151628AED2A6ABF7158809CF4F3C
    #data = 0xC0B7A8D05F3A829C


    # Encrpytion
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= data
    helperAES.io.cmd.payload.enc    <= 1  # do an encryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0

    rtlEncryptedBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL encrypted", hex(rtlEncryptedBlock))


    yield Timer(1000)