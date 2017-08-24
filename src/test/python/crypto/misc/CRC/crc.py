""" Classes to calculate CRCs (Cyclic Redundancy Check).

  License::

    Copyright (C) 2015-2016 by Martin Scharrer <martin@scharrer-online.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
from base import CrccheckBase, reflectbitorder, REFLECT_BIT_ORDER_TABLE


class CrcBase(CrccheckBase):
    """Abstract base class for all Cyclic Redundancy Checks (CRC) checksums"""
    _width = 0
    _poly = 0x00
    _initvalue = 0x00
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = None
    _check_data = bytearray(b"123456789")

    def process(self, data):
        """ Process given data.

            Args:
                data (bytes, bytearray or list of ints [0-255]): input data to process.

            Returns:
                self
        """
        crc = self._value
        highbit = 1 << (self._width - 1)
        mask = ((highbit - 1) << 1) | 0x1  # done this way to avoid overrun for 64-bit values
        poly = self._poly
        shift = self._width - 8
        diff8 = -shift
        if diff8 > 0:
            # enlarge temporary to fit 8-bit
            mask = 0xFF
            crc <<= diff8
            shift = 0
            highbit = 0x80
            poly = self._poly << diff8

        reflect = self._reflect_input
        for byte in data:
            if reflect:
                byte = REFLECT_BIT_ORDER_TABLE[byte]
            crc ^= (byte << shift)
            for i in range(0, 8):
                if crc & highbit:
                    crc = (crc << 1) ^ poly
                else:
                    crc = (crc << 1)
            crc &= mask
        if diff8 > 0:
            crc >>= diff8
        self._value = crc
        return self

    def final(self):
        """ Return final CRC value.

            Return:
                int: final CRC value
        """
        crc = self._value
        if self._reflect_output:
            crc = reflectbitorder(self._width, crc)
        crc ^= self._xor_output
        return crc


class Crc(CrcBase):
    """ Creates a new general (user-defined) CRC calculator instance.

        Arguments:
            width (int): bit width of CRC.
            poly (int): polynomial of CRC with the top bit omitted.
            initvalue (int): initial value of internal running CRC value. Usually either 0 or (1<<width)-1,
                i.e. "all-1s".
            reflect_input (bool): If true the bit order of the input bytes are reflected first.
                This is to calculate the CRC like least-significant bit first systems will do it.
            reflect_output (bool): If true the bit order of the calculation result will be reflected before
                the XOR output stage.
            xor_output (int): The result is bit-wise XOR-ed with this value. Usually 0 (value stays the same) or
                (1<<width)-1, i.e. "all-1s" (invert value).
            check_result (int): The expected result for the check input "123456789" (= [0x31, 0x32, 0x33, 0x34,
                0x35, 0x36, 0x37, 0x38, 0x39]). This value is used for the selftest() method to verify proper
                operation.
    """
    _width = 0
    _poly = 0x00
    _initvalue = 0x00
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = None

    def __init__(self, width, poly, initvalue=0x00, reflect_input=False, reflect_output=False, xor_output=0x00,
                 check_result=0x00):
        super(Crc, self).__init__(initvalue)
        self._width = width
        self._poly = poly
        self._reflect_input = reflect_input
        self._reflect_output = reflect_output
        self._xor_output = xor_output
        self._check_result = check_result


class Crc8(CrcBase):
    """CRC-8.
       Has optimised code for 8-bit CRCs and is used as base class for all other CRC with this width.
    """
    _width = 8
    _poly = 0x07
    _initvalue = 0xFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFF
    _check_result = 0xF4

    def process(self, data):
        """ Process given data.

            Args:
                data (bytes, bytearray or list of ints [0-255]): input data to process.

            Returns:
                self
        """
        crc = self._value

        reflect = self._reflect_input
        poly = self._poly
        for byte in data:
            if reflect:
                byte = REFLECT_BIT_ORDER_TABLE[byte]
            crc = crc ^ byte
            for i in range(0, 8):
                if crc & 0x80:
                    crc = (crc << 1) ^ poly
                else:
                    crc = (crc << 1)
            crc &= 0xFF
        self._value = crc
        return self


class Crc16(CrcBase):
    """CRC-16.
       Has optimised code for 16-bit CRCs and is used as base class for all other CRC with this width.
    """
    _width = 16
    _poly = 0x1021
    _initvalue = 0xFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFF
    _check_result = 0x31C3

    def process(self, data):
        """ Process given data.

            Args:
                data (bytes, bytearray or list of ints [0-255]): input data to process.

            Returns:
                self
        """
        crc = self._value

        reflect = self._reflect_input
        poly = self._poly
        for byte in data:
            if reflect:
                byte = REFLECT_BIT_ORDER_TABLE[byte]
            crc ^= (byte << 8)
            for i in range(0, 8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ poly
                else:
                    crc = (crc << 1)
            crc &= 0xFFFF
        self._value = crc
        return self


class Crc32(CrcBase):
    """CRC-32.
       Has optimised code for 32-bit CRCs and is used as base class for all other CRC with this width.
    """
    _width = 32
    _poly = 0x04C11DB7
    _initvalue = 0xFFFFFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFFFFFF
    _check_result = 0xCBF43926

    def process(self, data):
        """ Process given data.

            Args:
                data (bytes, bytearray or list of ints [0-255]): input data to process.

            Returns:
                self
        """
        crc = self._value

        reflect = self._reflect_input
        poly = self._poly
        for byte in data:
            if reflect:
                byte = REFLECT_BIT_ORDER_TABLE[byte]
            crc ^= (byte << 24)
            for i in range(0, 8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ poly
                else:
                    crc = (crc << 1)
            crc &= 0xFFFFFFFF
        self._value = crc
        return self


class Crc3Rohc(CrcBase):
    """CRC-3/ROHC"""
    _width = 3
    _poly = 0x3
    _initvalue = 0x7
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0
    _check_result = 0x6


class Crc4Itu(CrcBase):
    """CRC-4/ITU"""
    _width = 4
    _poly = 0x3
    _initvalue = 0x0
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0
    _check_result = 0x7


class Crc5Epc(CrcBase):
    """CRC-5/EPC"""
    _width = 5
    _poly = 0x09
    _initvalue = 0x09
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0x00


class Crc5Itu(CrcBase):
    """CRC-5/ITU"""
    _width = 5
    _poly = 0x15
    _initvalue = 0x00
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x07


class Crc5Usb(CrcBase):
    """CRC-5/USB"""
    _width = 5
    _poly = 0x05
    _initvalue = 0x1F
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x1F
    _check_result = 0x19


class Crc6Cdma2000A(CrcBase):
    """CRC-6/CDMA2000-A"""
    _width = 6
    _poly = 0x27
    _initvalue = 0x3F
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0x0D


class Crc6Cdma2000B(CrcBase):
    """CRC-6/CDMA2000-B"""
    _width = 6
    _poly = 0x07
    _initvalue = 0x3F
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0x3B


class Crc6Darc(CrcBase):
    """CRC-6/DARC"""
    _width = 6
    _poly = 0x19
    _initvalue = 0x00
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x26


class Crc6Itu(CrcBase):
    """CRC-6/ITU"""
    _width = 6
    _poly = 0x03
    _initvalue = 0x00
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x06


class Crc7(CrcBase):
    """CRC-7"""
    _width = 7
    _poly = 0x09
    _initvalue = 0x00
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0x75


class Crc7Rohc(CrcBase):
    """CRC-7/ROHC"""
    _width = 7
    _poly = 0x4F
    _initvalue = 0x7F
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x53


class Crc8Cdma2000(Crc8):
    """CRC-8/CDMA2000"""
    _width = 8
    _poly = 0x9B
    _initvalue = 0xFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0xDA


class Crc8Darc(Crc8):
    """CRC-8/DARC"""
    _width = 8
    _poly = 0x39
    _initvalue = 0x00
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x15


class Crc8DvbS2(Crc8):
    """CRC-8/DVB-S2"""
    _width = 8
    _poly = 0xD5
    _initvalue = 0x00
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0xBC


class Crc8Ebu(Crc8):
    """CRC-8/EBU"""
    _width = 8
    _poly = 0x1D
    _initvalue = 0xFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x97


class Crc8ICode(Crc8):
    """CRC-8/I-CODE"""
    _width = 8
    _poly = 0x1D
    _initvalue = 0xFD
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00
    _check_result = 0x7E


class Crc8Itu(Crc8):
    """CRC-8/ITU"""
    _width = 8
    _poly = 0x07
    _initvalue = 0x00
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x55
    _check_result = 0xA1


class Crc8Maxim(Crc8):
    """CRC-8/MAXIM"""
    _width = 8
    _poly = 0x31
    _initvalue = 0x00
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0xA1


class Crc8Rohc(Crc8):
    """CRC-8/ROHC"""
    _width = 8
    _poly = 0x07
    _initvalue = 0xFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0xD0


class Crc8Wcdma(Crc8):
    """CRC-8/WCDMA"""
    _width = 8
    _poly = 0x9B
    _initvalue = 0x00
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00
    _check_result = 0x25


class Crc10(CrcBase):
    """CRC-10"""
    _width = 10
    _poly = 0x233
    _initvalue = 0x000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000
    _check_result = 0x199


class Crc10Cdma2000(CrcBase):
    """CRC-10/CDMA2000"""
    _width = 10
    _poly = 0x3D9
    _initvalue = 0x3FF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000
    _check_result = 0x233


class Crc11(CrcBase):
    """CRC-11"""
    _width = 11
    _poly = 0x385
    _initvalue = 0x01A
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000
    _check_result = 0x5A3


class Crc123Gpp(CrcBase):
    """CRC-12/3GPP"""
    _width = 12
    _poly = 0x80F
    _initvalue = 0x000
    _reflect_input = False
    _reflect_output = True
    _xor_output = 0x000
    _check_result = 0xDAF


class Crc12Cdma2000(CrcBase):
    """CRC-12/CDMA2000"""
    _width = 12
    _poly = 0xF13
    _initvalue = 0xFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000
    _check_result = 0xD4D


class Crc12Dect(CrcBase):
    """CRC-12/DECT"""
    _width = 12
    _poly = 0x80F
    _initvalue = 0x000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000
    _check_result = 0xF5B


class Crc13Bbc(CrcBase):
    """CRC-13/BBC"""
    _width = 13
    _poly = 0x1CF5
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x04FA


class Crc14Darc(CrcBase):
    """CRC-14/DARC"""
    _width = 14
    _poly = 0x0805
    _initvalue = 0x0000
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0x082D


class Crc15(CrcBase):
    """CRC-15"""
    _width = 15
    _poly = 0x4599
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x059E


class Crc15Mpt1327(CrcBase):
    """CRC-15/MPT1327"""
    _width = 15
    _poly = 0x6815
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0001
    _check_result = 0x2566


class CrcArc(Crc16):
    """ARC"""
    _width = 16
    _poly = 0x8005
    _initvalue = 0x0000
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0xBB3D


class Crc16AugCcitt(Crc16):
    """CRC-16/AUG-CCITT"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0x1D0F
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0xE5CC


class Crc16Buypass(Crc16):
    """CRC-16/BUYPASS"""
    _width = 16
    _poly = 0x8005
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0xFEE8


class Crc16CcittFalse(Crc16):
    """CRC-16/CCITT-FALSE"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0xFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x29B1


class Crc16Cdma2000(Crc16):
    """CRC-16/CDMA2000"""
    _width = 16
    _poly = 0xC867
    _initvalue = 0xFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x4C06


class Crc16Dds110(Crc16):
    """CRC-16/DDS-110"""
    _width = 16
    _poly = 0x8005
    _initvalue = 0x800D
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x9ECF


class Crc16DectR(Crc16):
    """CRC-16/DECT-R"""
    _width = 16
    _poly = 0x0589
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0001
    _check_result = 0x007E


class Crc16DectX(Crc16):
    """CRC-16/DECT-X"""
    _width = 16
    _poly = 0x0589
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x007F


class Crc16Dnp(Crc16):
    """CRC-16/DNP"""
    _width = 16
    _poly = 0x3D65
    _initvalue = 0x0000
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFF
    _check_result = 0xEA82


class Crc16En13757(Crc16):
    """CRC-16/EN-13757"""
    _width = 16
    _poly = 0x3D65
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFF
    _check_result = 0xC2B7


class Crc16Genibus(Crc16):
    """CRC-16/GENIBUS"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0xFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFF
    _check_result = 0xD64E


class Crc16Maxim(Crc16):
    """CRC-16/MAXIM"""
    _width = 16
    _poly = 0x8005
    _initvalue = 0x0000
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFF
    _check_result = 0x44C2


class Crcc16Mcrf4xx(Crc16):
    """CRC-16/MCRF4XX"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0xFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0x6F91


class Crc16Riello(Crc16):
    """CRC-16/RIELLO"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0xB2AA
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0x63D0


class Crc16T10Dif(Crc16):
    """CRC-16/T10-DIF"""
    _width = 16
    _poly = 0x8BB7
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0xD0DB


class Crc16Teledisk(Crc16):
    """CRC-16/TELEDISK"""
    _width = 16
    _poly = 0xA097
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x0FB3


class Crc16Tms37157(Crc16):
    """CRC-16/TMS37157"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0x89EC
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0x26B1


class Crc16Usb(Crc16):
    """CRC-16/USB"""
    _width = 16
    _poly = 0x8005
    _initvalue = 0xFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFF
    _check_result = 0xB4C8


class CrcA(Crc16):
    """CRC-A"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0xC6C6
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0xBF05


class Crc16Ccitt(Crc16):
    """CRC16 CCITT, aka KERMIT"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0x0000
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0x2189


CrcKermit = Crc16Ccitt


class CrcModbus(CrcBase):
    """MODBUS"""
    _width = 16
    _poly = 0x8005
    _initvalue = 0xFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x0000
    _check_result = 0x4B37


class CrcX25(CrcBase):
    """X-25"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0xFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFF
    _check_result = 0x906E


class CrcXmodem(CrcBase):
    """XMODEM"""
    _width = 16
    _poly = 0x1021
    _initvalue = 0x0000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000
    _check_result = 0x31C3


class Crc24(CrcBase):
    """CRC-24"""
    _width = 24
    _poly = 0x864CFB
    _initvalue = 0xB704CE
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000000
    _check_result = 0x21CF02


class Crc24FlexrayA(CrcBase):
    """CRC-24/FLEXRAY-A"""
    _width = 24
    _poly = 0x5D6DCB
    _initvalue = 0xFEDCBA
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000000
    _check_result = 0x7979BD


class Crc24FlexrayB(CrcBase):
    """CRC-24/FLEXRAY-B"""
    _width = 24
    _poly = 0x5D6DCB
    _initvalue = 0xABCDEF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x000000
    _check_result = 0x1F23B8


class Crc31Philips(CrcBase):
    """CRC-31/PHILIPS"""
    _width = 31
    _poly = 0x04C11DB7
    _initvalue = 0x7FFFFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x7FFFFFFF
    _check_result = 0x0CE9E46C


class Crc32Bzip2(Crc32):
    """CRC-32/BZIP2"""
    _width = 32
    _poly = 0x04C11DB7
    _initvalue = 0xFFFFFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFFFFFF
    _check_result = 0xFC891918


class Crc32c(Crc32):
    """CRC-32C"""
    _width = 32
    _poly = 0x1EDC6F41
    _initvalue = 0xFFFFFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFFFFFF
    _check_result = 0xE3069283


class Crc32d(Crc32):
    """CRC-32D"""
    _width = 32
    _poly = 0xA833982B
    _initvalue = 0xFFFFFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFFFFFF
    _check_result = 0x87315576


class Crc32Mpeg2(Crc32):
    """CRC-32/MPEG-2"""
    _width = 32
    _poly = 0x04C11DB7
    _initvalue = 0xFFFFFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00000000
    _check_result = 0x0376E6E7


class Crc32Posix(Crc32):
    """CRC-32/POSIX"""
    _width = 32
    _poly = 0x04C11DB7
    _initvalue = 0x00000000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFFFFFF
    _check_result = 0x765E7680


class Crc32q(Crc32):
    """CRC-32Q"""
    _width = 32
    _poly = 0x814141AB
    _initvalue = 0x00000000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00000000
    _check_result = 0x3010BF7F


class CrcJamcrc(Crc32):
    """JAMCRC"""
    _width = 32
    _poly = 0x04C11DB7
    _initvalue = 0xFFFFFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x00000000
    _check_result = 0x340BC6D9


class CrcXfer(Crc32):
    """XFER"""
    _width = 32
    _poly = 0x000000AF
    _initvalue = 0x00000000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x00000000
    _check_result = 0xBD0BE338


class Crc40Gsm(CrcBase):
    """CRC-40/GSM"""
    _width = 40
    _poly = 0x0004820009
    _initvalue = 0x0000000000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFFFFFFFF
    _check_result = 0xD4164FC646


class Crc64(CrcBase):
    """CRC-64"""
    _width = 64
    _poly = 0x42F0E1EBA9EA3693
    _initvalue = 0x0000000000000000
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0x0000000000000000
    _check_result = 0x6C40DF5F0B497347


class Crc64We(CrcBase):
    """CRC-64/WE"""
    _width = 64
    _poly = 0x42F0E1EBA9EA3693
    _initvalue = 0xFFFFFFFFFFFFFFFF
    _reflect_input = False
    _reflect_output = False
    _xor_output = 0xFFFFFFFFFFFFFFFF
    _check_result = 0x62EC59E3F1A4F00A


class Crc64Xz(CrcBase):
    """CRC-64/XZ"""
    _width = 64
    _poly = 0x42F0E1EBA9EA3693
    _initvalue = 0xFFFFFFFFFFFFFFFF
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0xFFFFFFFFFFFFFFFF
    _check_result = 0x995DC9BBDF1939FA


class Crc82Darc(CrcBase):
    """CRC-82/DARC"""
    _width = 82
    _poly = 0x0308C0111011401440411
    _initvalue = 0x000000000000000000000
    _reflect_input = True
    _reflect_output = True
    _xor_output = 0x000000000000000000000
    _check_result = 0x09EA83F625023801FD612


ALLCRCCLASSES = (
    Crc3Rohc, Crc4Itu, Crc5Epc, Crc5Itu, Crc5Usb, Crc6Cdma2000A, Crc6Cdma2000B, Crc6Darc, Crc6Itu, Crc7, Crc7Rohc,
    Crc8, Crc8Cdma2000, Crc8Darc, Crc8DvbS2, Crc8Ebu, Crc8ICode, Crc8Itu, Crc8Maxim, Crc8Rohc, Crc8Wcdma, Crc10,
    Crc10Cdma2000, Crc11, Crc123Gpp, Crc12Cdma2000, Crc12Dect, Crc13Bbc, Crc14Darc, Crc15, Crc15Mpt1327, Crc16, CrcArc,
    Crc16AugCcitt, Crc16Buypass, Crc16CcittFalse, Crc16Cdma2000, Crc16Dds110, Crc16DectR, Crc16DectX, Crc16Dnp,
    Crc16En13757, Crc16Genibus, Crc16Maxim, Crcc16Mcrf4xx, Crc16Riello, Crc16T10Dif, Crc16Teledisk, Crc16Tms37157,
    Crc16Usb, CrcA, Crc16Ccitt, CrcKermit, CrcModbus, CrcX25, CrcXmodem, Crc24, Crc24FlexrayA, Crc24FlexrayB,
    Crc31Philips, Crc32, Crc32Bzip2, Crc32c, Crc32d, Crc32Mpeg2, Crc32Posix, Crc32q, CrcJamcrc, CrcXfer, Crc40Gsm,
    Crc64, Crc64We, Crc64Xz, Crc82Darc
)

