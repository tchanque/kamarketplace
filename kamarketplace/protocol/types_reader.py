import struct

class Data:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.remaining = self.data

    def read(self, bytes_to_read):
        result = self.data[self.pos: self.pos + bytes_to_read]
        self.pos += bytes_to_read
        self.remaining = self.data[self.pos:]
        return result

    def read_double(self):
        print("Reading double from %s" % self.remaining)
        return struct.unpack("!d", self.read(8))[0]

    def read_boolean(self):
        ans = self.read(1)
        assert ans[0] in [0, 1]
        return bool(ans[0])

    def read_byte(self, byte_number=1):
        print("Reading byte from %s" % self.remaining)
        return int.from_bytes(self.read(byte_number), byteorder="big", signed=True)

    def read_unsigned_byte(self):
        return int.from_bytes(self.read(1), "big")

    def read_bytearray(self):
        lon = self.readVarInt()
        return self.read(lon)

    def read_float(self):
        print("Reading float from %s" % self.remaining)
        return struct.unpack("!f", self.read(4))[0]

    def read_int(self):
        print("Reading integer from %s" % self.remaining)
        return int.from_bytes(self.read(4), byteorder="big", signed=True)

    def read_short(self):
        print("Reading short from %s" % self.remaining)
        return int.from_bytes(self.read(2), byteorder="big", signed=True)

    def read_utf(self):
        length = self.read_unsignedshort()
        print("Decoding UTF from %s" % self.remaining)
        return self.read(length).decode()

    def read_unsignedbyte(self):
        print("Reading unsigned byte from %s" % self.remaining)
        return int.from_bytes(self.read(1), "big")

    def read_unsignedint(self):
        print("Reading unsigned integer from %s" % self.remaining)
        return int.from_bytes(self.read(4), "big")

    def read_unsignedshort(self):
        print("Reading unsigned short from %s" % self.remaining)
        return int.from_bytes(self.read(2), byteorder="big")

    def read_varint(self):
        print("Reading unsigned var integer from %s" % self.remaining)
        ans = 0
        for i in range(0, 32, 7):
            b = self.read_unsignedbyte()
            ans += (b & 0b01111111) << i
            if not b & 0b10000000:
                return ans
        raise Exception("Too much data")

    def read_varlong(self):
        print("Reading var long from %s" % self.remaining)
        ans = 0
        for i in range(0, 64, 7):
            b = self.read_unsigned_byte()
            ans += (b & 0b01111111) << i
            if not b & 0b10000000:
                return ans
        raise Exception("Too much data")

    def read_varshort(self):
        ans = 0
        for i in range(0, 16, 7):
            b = self.read_byte()
            ans += (b & 0b01111111) << i
            if not b & 0b10000000:
                return ans
        raise Exception("Too much data")

    def read_varuhint(self):
        return self.read_varint()

    def read_varuhlong(self):
        return self.read_varlong()

    def read_varuhshort(self):
        return self.read_varshort()


DIC_TYPES = {
    'Boolean': Data.read_boolean,
    'Byte': Data.read_byte,
    'ByteArray': Data.read_bytearray,
    'Double': Data.read_double,
    'Float': Data.read_float,
    'Int': Data.read_int,
    'Short': Data.read_short,
    'UTF': Data.read_utf,
    'UnsignedByte': Data.read_unsignedbyte,
    'UnsignedInt': Data.read_unsignedint,
    'UnsignedShort': Data.read_unsignedshort,
    'VarInt': Data.read_varint,
    'VarLong': Data.read_varlong,
    'VarShort': Data.read_varshort,
    'VarUhInt': Data.read_varuhint,
    'VarUhLong': Data.read_varuhlong,
    'VarUhShort': Data.read_varuhshort
}
