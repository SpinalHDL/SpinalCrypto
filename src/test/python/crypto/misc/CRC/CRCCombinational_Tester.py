###############################################################################
# Test the CRC32, CRC16 and CRC8
#
###############################################################################

import cocotb
from cocotb.triggers import RisingEdge, Timer

from crc import *
from spinal.common.Flow import Flow

from spinal.common.ClockDomain  import ClockDomain, RESET_ACTIVE_LEVEL
from spinal.common.misc         import assertEquals


###############################################################################
# CRC Helper
class CRCHelper:

    def __init__(self, dut, prefixName):
        self.io = CRCHelper.IO(dut, prefixName)

    #==========================================================================
    # IO
    #==========================================================================
    class IO:

        def __init__(self, dut, prefixName):
            self.cmd      = Flow(dut, prefixName+"_cmd")
            self.rspValid = dut.__getattr__(prefixName + "_rsp_valid")
            self.rspCRC   = dut.__getattr__(prefixName + "_rsp_payload")


        def init(self):
            self.cmd.valid        <= 0
            self.cmd.payload.data <= 0


    #==========================================================================
    # CMD
    #==========================================================================
    class CMD:
        INIT   = 0
        UPDATE = 1


###############################################################################
# Test a sequence of read
@cocotb.test()
def test_crc32(dut):

    dut.log.info("Cocotb CRC32 test")

    crc32 = CRCHelper(dut, "io_crc32")
    clockDomain  = ClockDomain(dut.clk, 5, reset=None, resetActiveLevel=RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    crc32.io.init()

    # data to crc
    data = [0x00000001, 0x02000000,  0x32546789, 0x12435423]

    yield RisingEdge(dut.clk)

    # init value for the CRC
    crc32.io.cmd.valid <= 1
    crc32.io.cmd.payload.mode <= CRCHelper.CMD.INIT

    yield RisingEdge(dut.clk)

    for index in range(0, len(data)):

        crc32.io.cmd.valid <= 1
        crc32.io.cmd.payload.data <= data[index]
        crc32.io.cmd.payload.mode <= CRCHelper.CMD.UPDATE

        dataArray = bytearray.fromhex("".join(['{0:08x}'.format(data[i]) for i in range(0, index+1)]))
        crcModel  = Crc32.calc(dataArray)

        yield RisingEdge(dut.clk)

        crc32.io.cmd.valid <= 0
        yield RisingEdge(dut.clk)

        crcRTL = int(crc32.io.rspCRC)

        yield RisingEdge(dut.clk)

        assertEquals(crcRTL, crcModel, "CRC32 : RTL is not equal to the model (%X =/= %X)" % (crcRTL, crcModel))


    dut.log.info("Cocotb CRC32 test")

#
#
# ###############################################################################
# # Test a sequence of read
# @cocotb.test()
# def test_crc16(dut):
#
#     dut.log.info("Cocotb CRC16 test")
#
#     crc16 = CRCHelper(dut, "io_crc16")
#     clockDomain  = ClockDomain(dut.clk, 5, dut.resetn, RESET_ACTIVE_LEVEL.LOW)
#
#     # Start clock
#     cocotb.fork(clockDomain.start())
#
#     # Init IO and wait the end of the reset
#     crc16.io.init()
#
#     # data to crc
#     data = [0x0000, 0x0200,  0x6789, 0x1243]
#
#     yield clockDomain.event_endReset.wait()
#
#     # init value for the CRC
#     crc16.io.cmd.valid <= 1
#     crc16.io.cmd.payload.mode <= CRCHelper.CMD.INIT
#
#     yield RisingEdge(dut.clk)
#     yield RisingEdge(dut.clk)
#
#     for index in range(0, len(data)):
#
#         crc16.io.cmd.valid <= 1
#         crc16.io.cmd.payload.data <= data[index]
#         if index < len(data)-1:
#             crc16.io.cmd.payload.mode <= CRCHelper.CMD.UPDATE
#         else:
#             crc16.io.cmd.payload.mode <= CRCHelper.CMD.FINAL
#
#         print("heloo", "".join('{0:04x}'.format(data[index])))
#         dataArray = bytearray.fromhex("".join(['{0:04x}'.format(data[i]) for i in range(0, index+1)]))
#         crcModel  = Crc16.calc(dataArray)
#
#         yield RisingEdge(dut.clk)
#
#         crc16.io.cmd.valid <= 0
#         yield RisingEdge(dut.clk)
#
#         crcRTL = int(crc16.io.rspCRC)
#
#         yield RisingEdge(dut.clk)
#
#         #assertEquals(crcRTL, crcModel, "CRC16 : RTL is not equal to the model (%X =/= %X)" % (crcRTL, crcModel))
#         print(hex(crcRTL), hex(crcModel))
#         print('{0:016b}'.format(crcRTL))
#         print('{0:016b}'.format(crcModel))
#
#
#     dut.log.info("Cocotb CRC16 test")
#
#
# ###############################################################################
# # Test a sequence of read
# @cocotb.test()
# def test_crc8(dut):
#
#     dut.log.info("Cocotb CRC8 test")
#
#     crc8 = CRCHelper(dut, "io_crc8")
#     clockDomain  = ClockDomain(dut.clk, 5, dut.resetn, RESET_ACTIVE_LEVEL.LOW)
#
#     # Start clock
#     cocotb.fork(clockDomain.start())
#
#     # Init IO and wait the end of the reset
#     crc8.io.init()
#
#     # data to crc
#     data = [0x00, 0x02,  0x67, 0x43]
#
#     yield clockDomain.event_endReset.wait()
#
#     # init value for the CRC
#     crc8.io.cmd.valid <= 1
#     crc8.io.cmd.payload.mode <= CRCHelper.CMD.INIT
#
#     yield RisingEdge(dut.clk)
#     crc8.io.cmd.valid <= 0
#     yield RisingEdge(dut.clk)
#
#     for index in range(0, len(data)):
#
#         crc8.io.cmd.valid <= 1
#         crc8.io.cmd.payload.data <= data[index]
#         if index < len(data)-1:
#             crc8.io.cmd.payload.mode <= CRCHelper.CMD.UPDATE
#         else:
#             crc8.io.cmd.payload.mode <= CRCHelper.CMD.FINAL
#
#         print("heloo", "".join('{0:02x}'.format(data[index])))
#         dataArray = bytearray.fromhex("".join(['{0:02x}'.format(data[i]) for i in range(0, index+1)]))
#         crcModel  = Crc8.calc(dataArray)
#
#         yield RisingEdge(dut.clk)
#
#         crc8.io.cmd.valid <= 0
#         yield RisingEdge(dut.clk)
#
#         crcRTL = int(crc8.io.rspCRC)
#
#         yield RisingEdge(dut.clk)
#
#         #assertEquals(crcRTL, crcModel, "CRC16 : RTL is not equal to the model (%X =/= %X)" % (crcRTL, crcModel))
#         print(hex(crcRTL), hex(crcModel))
#         print('{0:08b}'.format(crcRTL))
#         print('{0:08b}'.format(crcModel))
#
#
#     dut.log.info("Cocotb CRC8 test")