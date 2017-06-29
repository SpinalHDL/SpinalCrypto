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
def testAESCore(dut):
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

