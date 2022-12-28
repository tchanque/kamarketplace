class Packet:
    def __init__(self, packet_payload):
        self.payload = packet_payload
        self.header = self.get_header()
        self.id = self.get_id()
        self.size_of_size = self.get_size_of_size()
        self.size_packet = self.get_size_packet()
        self.size_message = self.get_size_message()
        self.bin_header = self.get_bin_header()

    def get_header(self):
        return ''.join(self.payload.split(':')[:2])

    def get_bin_header(self):
        scale = 16  # hexadecimal
        num_of_bits = 16
        header = self.header

        return bin(int(header, scale))[2:].zfill(num_of_bits)

    def get_id(self):
        if ~hasattr(self, "bin_header"):
            self.bin_header = self.get_bin_header()

        return int(self.bin_header[:14], 2)

    def get_size_of_size(self):
        if ~hasattr(self, "bin_header"):
            self.bin_header = self.get_bin_header()
        return int(self.bin_header[-2:], 2)

    def get_size_packet(self):
        return ''.join(self.payload.split(":")[2: 2 + self.size_of_size])

    def get_size_message(self):
        return int(self.size_packet, base=16)
