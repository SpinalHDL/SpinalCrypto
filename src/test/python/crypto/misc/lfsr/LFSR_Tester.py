import cocotb
from cocotb.result import TestFailure
from cocotb.triggers import RisingEdge
from cocotblib.misc import assertEquals, randInt

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from crypto.misc.lfsr.LFSR import *



###############################################################################
# Fibonacci LFSR
#
@cocotb.test()
def test_fibonacci(dut):

    orderPolynomial = 8

    dut.log.info("Cocotb test LFSR fibonacci")

    clockDomain  = ClockDomain(dut.clk, 500, None , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    dut.io_fib_inc       <= 0
    dut.io_fib_init      <= 0
    dut.io_fib_seed      <= 0

    yield RisingEdge(dut.clk)
    yield RisingEdge(dut.clk)

    # init LFSR
    #widthData = 32
    #initValue = randInt(0, 2**widthData)
    dut.io_fib_init <= 1
    dut.io_fib_seed <= 1

    yield RisingEdge(dut.clk)

    dut.io_fib_init <= 0

    yield RisingEdge(dut.clk)

    listReg = []

    yield RisingEdge(dut.clk)

    dut.io_fib_inc <= 1

    for _ in range(0, 2**orderPolynomial-1):

        yield RisingEdge(dut.clk)

        binValue = int(dut.io_fib_value)

        if binValue in listReg:
            raise TestFailure("This value has been already generated !!")

        listReg.append(binValue)

        #print('{0:07b}'.format(binValue), hex(binValue))


    if len(listReg) != 2**orderPolynomial-1:
        raise TestFailure("The maximum length of the LFSR has been not reached")

    dut.io_fib_inc <= 0

    yield RisingEdge(dut.clk)


    dut.log.info("Cocotb test LFSR fibonacci")



###############################################################################
# Galois LSFR
#
@cocotb.test()
def test_galois(dut):

    orderPolynomial = 8

    dut.log.info("Cocotb test LFSR Galois")

    clockDomain  = ClockDomain(dut.clk, 500, None , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    dut.io_gal_inc       <= 0
    dut.io_gal_init      <= 0
    dut.io_gal_seed      <= 0

    yield RisingEdge(dut.clk)
    yield RisingEdge(dut.clk)

    # init LFSR
    widthData = 16
    initValue = randInt(0, 2**widthData)
    dut.io_gal_init <= 1
    dut.io_gal_seed <= 255

    yield RisingEdge(dut.clk)

    dut.io_gal_init <= 0

    yield RisingEdge(dut.clk)

    listReg = []

    yield RisingEdge(dut.clk)

    dut.io_gal_inc <= 1


    for _ in range(0, 2**orderPolynomial-1):

        yield RisingEdge(dut.clk)

        binValue = int(dut.io_gal_value)

        if binValue in listReg:
            raise TestFailure("This value has been already generated !!")

        listReg.append(binValue)

        #print('{0:07b}'.format(binValue), hex(binValue))


    if len(listReg) != 2**orderPolynomial-1:
        raise TestFailure("The maximum length of the LFSR has been not reached")

    dut.io_gal_inc <= 0

    yield RisingEdge(dut.clk)

    dut.log.info("Cocotb test LFSR galois")

