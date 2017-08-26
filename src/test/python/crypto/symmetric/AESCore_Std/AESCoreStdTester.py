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

    def __init__(self,dut, prefix):

        # IO definition -----------------------------------
        self.io = AESCoreStdHelper.IO(dut, prefix)

    #==========================================================================
    # Rename IO
    #==========================================================================
    class IO:

        def __init__ (self, dut, prefix):
            self.cmd    = Stream(dut, prefix + "_cmd")
            self.rsp    = Flow(dut, prefix +  "_rsp")
            self.clk    = dut.clk
            self.resetn = dut.resetn

        def init(self):
            self.cmd.valid          <= 0
            self.cmd.payload.block  <= 0
            self.cmd.payload.key    <= 0
            self.cmd.payload.enc    <= 0




###############################################################################
# Test AES Core 128
#
#@cocotb.test()
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
    dut.log.info("Cocotb test AES Core 128")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperAES    = AESCoreStdHelper(dut, "io_aes_128")
    clockDomain  = ClockDomain(helperAES.io.clk, 200, helperAES.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperAES.io.init()
    yield clockDomain.event_endReset.wait()

    # start monitoring the Valid signal
    helperAES.io.rsp.startMonitoringValid(helperAES.io.clk)


    # Vector test (Encryption)

    # Vector 0
    plain  = 0x3243f6a8885a308d313198a2e0370734 # encrypt vector
    key    = 0x2B7E151628AED2A6ABF7158809CF4F3C
    cipher = 0x3925841d02dc09fbDC118597196A0b32 # decrypt vector

    # Vector 1
    #plain  = 0x11111111AAAAAAAA55555555DDDDDDDD# encrypt vector
    #key    = 0x44444444444444444444444444444444
    #cipher = 0x614afa11507ac929b68138d8b896aefb # decrypt vector

    # Encrpytion
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= plain
    helperAES.io.cmd.payload.enc    <= 1  # do an encryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0


    #data = 0x3925841d02dc09fbDC118597196A0b32 # decrypt vector

    rtlCipherBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL Cipher", hex(rtlCipherBlock))

    yield RisingEdge(helperAES.io.clk)

    # DECYPTION
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= cipher
    helperAES.io.cmd.payload.enc    <= 0  # do an decryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0


    rtlPlainBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL Plain", hex(rtlPlainBlock))

    yield RisingEdge(helperAES.io.clk)



    yield Timer(1000)

###############################################################################
# Test AES Core 192
#
@cocotb.test()
def testAESCore192_Std(dut):

    #########
    dut.log.info("Cocotb test AES Core 192")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperAES    = AESCoreStdHelper(dut, "io_aes_192")
    clockDomain  = ClockDomain(helperAES.io.clk, 200, helperAES.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperAES.io.init()
    yield clockDomain.event_endReset.wait()

    # start monitoring the Valid signal
    helperAES.io.rsp.startMonitoringValid(helperAES.io.clk)


    # Vector test (Encryption)

    # Vector 0
    plain  = 0x3243f6a8885a308d313198a2e0370734 # encrypt vector
    key    = 0x000102030405060708090a0b0c0d0e0f1011121314151617
    cipher = 0xbc3aaab5d97baa7b325d7b8f69cd7ca8 # decrypt vector



    # Encrpytion
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= plain
    helperAES.io.cmd.payload.enc    <= 1  # do an encryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0




    rtlCipherBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL Cipher", hex(rtlCipherBlock))

    yield RisingEdge(helperAES.io.clk)

    # DECYPTION
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= cipher
    helperAES.io.cmd.payload.enc    <= 0  # do an decryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0


    rtlPlainBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL Plain", hex(rtlPlainBlock))

    yield RisingEdge(helperAES.io.clk)



    yield Timer(1000)



###############################################################################
# Test AES Core 256
#
#@cocotb.test()
def testAESCore256_Std(dut):

    #########
    dut.log.info("Cocotb test AES Core 256")
    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperAES    = AESCoreStdHelper(dut, "io_aes_256")
    clockDomain  = ClockDomain(helperAES.io.clk, 200, helperAES.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperAES.io.init()
    yield clockDomain.event_endReset.wait()

    # start monitoring the Valid signal
    helperAES.io.rsp.startMonitoringValid(helperAES.io.clk)


    # Vector test (Encryption)

    # Vector 0
    plain  = 0x3243f6a8885a308d313198a2e0370734 # encrypt vector
    key    = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    cipher = 0x9a198830ff9a4e39ec1501547d4a6b1bL # decrypt vector



    # Encrpytion
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= plain
    helperAES.io.cmd.payload.enc    <= 1  # do an encryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0


    #data = 0x3925841d02dc09fbDC118597196A0b32 # decrypt vector

    rtlCipherBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL Cipher", hex(rtlCipherBlock))

    yield RisingEdge(helperAES.io.clk)

    # DECYPTION
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= cipher
    helperAES.io.cmd.payload.enc    <= 0  # do an decryption


    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()

    helperAES.io.cmd.valid <= 0


    rtlPlainBlock = int(helperAES.io.rsp.event_valid.data.block)

    print("RTL Plain", hex(rtlPlainBlock))

    yield RisingEdge(helperAES.io.clk)



    yield Timer(1000)