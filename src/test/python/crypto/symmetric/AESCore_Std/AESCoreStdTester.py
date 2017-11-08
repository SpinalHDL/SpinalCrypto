import binascii

import random

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
# Generate random hex string
#
def randHexString(width):

    hexdigits = "0123456789ABCDEF"
    random_digits = "".join([ hexdigits[random.randint(0,0xF)] for _ in range(width) ])
    return random_digits


###############################################################################
# Test AES Core 128
#
@cocotb.test()
def testAESCore128_Std(dut):

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


    # Run patterns
    for _ in range(0,4):

        # Vector test (Encryption)
        #plain  = "3243f6a8885a308d313198a2e0370734"
        #key    = "2B7E151628AED2A6ABF7158809CF4F3C"
        #cipher = "3925841d02dc09fbDC118597196A0b32"

        # generate random vectors
        plain     = randHexString(32)
        key       = randHexString(32)
        keyByte   = key.decode("hex")
        plainByte = plain.decode("hex")

        # Model computation
        #######################################################################
        aes128     = AESModeOfOperationECB(keyByte)
        cipherRef  = aes128.encrypt(plainByte)

        #print("plain      " , plain)
        #print("key        " , key)
        #print("cipher ref " , binascii.hexlify(cipherRef))


        # RTL Encrpytion
        #######################################################################
        helperAES.io.cmd.valid          <= 1
        helperAES.io.cmd.payload.key    <= int(key, 16)
        helperAES.io.cmd.payload.block  <= int(plain, 16)
        helperAES.io.cmd.payload.enc    <= 1

        # Wait the end of the process and read the result
        yield helperAES.io.rsp.event_valid.wait()

        helperAES.io.cmd.valid <= 0

        cipherRTL = int(helperAES.io.rsp.event_valid.data.block)

        #print("RTL Cipher", hex(cipherRTL))
        assertEquals(int(binascii.hexlify(cipherRef), 16), cipherRTL, "Encryption AES128  data wrong ")

        yield RisingEdge(helperAES.io.clk)

        # RTL DECYPTION
        #######################################################################
        helperAES.io.cmd.valid          <= 1
        helperAES.io.cmd.payload.key    <= int(key, 16)
        helperAES.io.cmd.payload.block  <= int(binascii.hexlify(cipherRef), 16)
        helperAES.io.cmd.payload.enc    <= 0


        # Wait the end of the process and read the result
        yield helperAES.io.rsp.event_valid.wait()

        helperAES.io.cmd.valid <= 0

        plainRTL = int(helperAES.io.rsp.event_valid.data.block)

        #print("RTL Plain", hex(plainRTL))
        assertEquals(int(plain, 16), plainRTL, "Decryption AES128 data wrong ")

        yield RisingEdge(helperAES.io.clk)

        yield Timer(10)



###############################################################################
# Test AES Core 192
#
@cocotb.test()
def testAESCore192_Std(dut):

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


    # Run patterns
    for _ in range(0,4):

        # Vector test (Encryption)
        #plain  = "3243f6a8885a308d313198a2e0370734"
        #key    = "000102030405060708090a0b0c0d0e0f1011121314151617"
        #cipher = "bc3aaab5d97baa7b325d7b8f69cd7ca8"

        # generate random vectors
        plain     = randHexString(32)
        key       = randHexString(48)
        keyByte   = key.decode("hex")
        plainByte = plain.decode("hex")

        # Model computation
        #######################################################################
        aes192     = AESModeOfOperationECB(keyByte)
        cipherRef  = aes192.encrypt(plainByte)

        #print("plain      " , plain)
        #print("key        " , key)
        #print("cipher ref " , binascii.hexlify(cipherRef))

        # TRL Encrpytion
        #######################################################################
        helperAES.io.cmd.valid          <= 1
        helperAES.io.cmd.payload.key    <= int(key, 16)
        helperAES.io.cmd.payload.block  <= int(plain, 16)
        helperAES.io.cmd.payload.enc    <= 1


        # Wait the end of the process and read the result
        yield helperAES.io.rsp.event_valid.wait()

        helperAES.io.cmd.valid <= 0

        cipherRTL = int(helperAES.io.rsp.event_valid.data.block)

        #print("RTL Cipher", hex(cipherRTL))

        assertEquals(int(binascii.hexlify(cipherRef), 16), cipherRTL, "Encryption AES192  data wrong ")

        yield RisingEdge(helperAES.io.clk)

        # RTL Decryption
        #######################################################################
        helperAES.io.cmd.valid          <= 1
        helperAES.io.cmd.payload.key    <= int(key, 16)
        helperAES.io.cmd.payload.block  <= int(binascii.hexlify(cipherRef), 16)
        helperAES.io.cmd.payload.enc    <= 0  # do an decryption

        # Wait the end of the process and read the result
        yield helperAES.io.rsp.event_valid.wait()

        helperAES.io.cmd.valid <= 0

        plainRTL = int(helperAES.io.rsp.event_valid.data.block)

        assertEquals(int(plain, 16), plainRTL, "Decryption AES192 data wrong ")

        #print("RTL Plain", hex(plainRTL))

        yield RisingEdge(helperAES.io.clk)

        yield Timer(10)



###############################################################################
# Test AES Core 256
#
@cocotb.test()
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


    # Run patterns
    for _ in range(0,4):

        # Vector test (Encryption)
        #plain  = "3243f6a8885a308d313198a2e0370734"
        #key    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        #cipher = "9a198830ff9a4e39ec1501547d4a6b1b"

        # generate random vectors
        plain     = randHexString(32)
        key       = randHexString(64)
        keyByte   = key.decode("hex")
        plainByte = plain.decode("hex")


        # Model computation
        #######################################################################
        aes256     = AESModeOfOperationECB(keyByte)
        cipherRef  = aes256.encrypt(plainByte)

        #print("plain      " , plain)
        #print("key        " , key)
        #print("cipher ref " , binascii.hexlify(cipherRef))

        # RTL Encrpytion
        #######################################################################
        helperAES.io.cmd.valid          <= 1
        helperAES.io.cmd.payload.key    <= int(key, 16)
        helperAES.io.cmd.payload.block  <= int(plain, 16)
        helperAES.io.cmd.payload.enc    <= 1


        # Wait the end of the process and read the result
        yield helperAES.io.rsp.event_valid.wait()

        helperAES.io.cmd.valid <= 0

        cipherRTL = int(helperAES.io.rsp.event_valid.data.block)

        assertEquals(int(binascii.hexlify(cipherRef), 16), cipherRTL, "Encryption AES256  data wrong ")

        #print("RTL Cipher", hex(cipherRTL))

        yield RisingEdge(helperAES.io.clk)

        # RTL DECYPTION
        #######################################################################
        helperAES.io.cmd.valid          <= 1
        helperAES.io.cmd.payload.key    <= int(key, 16)
        helperAES.io.cmd.payload.block  <= int(binascii.hexlify(cipherRef), 16)
        helperAES.io.cmd.payload.enc    <= 0


        # Wait the end of the process and read the result
        yield helperAES.io.rsp.event_valid.wait()

        helperAES.io.cmd.valid <= 0

        plainRTL = int(helperAES.io.rsp.event_valid.data.block)

        assertEquals(int(plain, 16), plainRTL, "Decryption AES256 data wrong ")

        #print("RTL Plain", hex(plainRTL))

        yield RisingEdge(helperAES.io.clk)

        yield Timer(10)