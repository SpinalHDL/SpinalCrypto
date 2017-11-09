import cocotb
from cocotb.triggers import RisingEdge
from cocotblib.misc import assertEquals, randInt

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from crypto.misc.lfsr.LFSR import *



###############################################################################
# Fibonacci LFSR
#
@cocotb.test()
def test_fibonacci(dut):

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

    #lfsr = FibonacciLFSR(initValue, [0,2,3,5,10], widthData, LFSR_SHIFT_DIR.SHIFT_RIGHT)

    yield RisingEdge(dut.clk)

    dut.io_fib_init <= 0

    yield RisingEdge(dut.clk)
    yield RisingEdge(dut.clk)


    for _ in range(0, 258):
        dut.io_fib_inc <= 1

        yield RisingEdge(dut.clk)

        dut.io_fib_inc <= 0

        yield RisingEdge(dut.clk)

        print(hex(int(dut.io_fib_value)))

        #lfsr.getRand()
        #realResult = int(dut.io_fib_result)
        #assertEquals(lfsr.state, realResult, "LFSR Fibonacci Right - Comparaison Error %s - %s" % (hex(lfsr.state), hex(realResult)))


        yield RisingEdge(dut.clk)


    dut.io_fib_inc <= 0

    yield RisingEdge(dut.clk)


    dut.log.info("Cocotb test LFSR fibonacci Right")



###############################################################################
# Galois LSFR right
#
@cocotb.test()
def test_galois(dut):

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
    dut.io_gal_seed <= 1


    #lfsr = GaloisLFSR(initValue, [1,2], widthData, LFSR_SHIFT_DIR.SHIFT_RIGHT)

    yield RisingEdge(dut.clk)

    dut.io_gal_init <= 0

    yield RisingEdge(dut.clk)
    yield RisingEdge(dut.clk)


    for _ in range(0, 258):
        dut.io_gal_inc <= 1

        yield RisingEdge(dut.clk)

        dut.io_gal_inc <= 0

        yield RisingEdge(dut.clk)

        print(hex(int(dut.io_gal_value)))
        #lfsr.getRand()
        #realResult = int(dut.io_gal_result)

        #assertEquals(lfsr.state, realResult, "LFSR Galois Right - Comparaison Error python : %s - %s : hdl" % (hex(lfsr.state), hex(realResult)))

        yield RisingEdge(dut.clk)


    yield RisingEdge(dut.clk)


    dut.log.info("Cocotb test right LFSR galois")

