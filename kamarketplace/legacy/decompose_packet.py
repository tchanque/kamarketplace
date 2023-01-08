from kamarketplace import load_ids


def split_payload(payload):
    bytes_list = payload.split(':')

    header_byte = ':'.join(bytes_list[:2])
    body_byte = ':'.join(bytes_list[2:])

    return header_byte, body_byte


def convert_byte_to_hex(byte):
    return byte.replace(':', '')


def convert_hex_to_bin(hex_):
    # hex is in base 16
    return bin(int(hex_, 16))[2:]


def convert_hex_to_int(hex_):
    return int(hex_, 16)


def convert_byte_to_int(byte):
    hex_ = convert_byte_to_hex(byte)
    return convert_hex_to_int(hex_)


def convert_bin_to_int(bin_):
    return int(bin_, 2)


def convert_byte_to_bin(byte):
    hex_ = convert_byte_to_hex(byte)
    print("Converted byte in %s" % hex_)
    return convert_hex_to_bin(hex_)


def find_action(_id):
    dictionary = load_ids()
    return dictionary[str(_id)]


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARK_CYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def main(payload):
    print("%s Start decompiling the packet %s %s" % (Color.BOLD, payload, Color.END))
    print("***")
    print("%s %s Split header and body %s" % (Color.BOLD, Color.RED, Color.END))
    header_byte, body_byte = split_payload(payload)
    print("The header is " + header_byte)
    print("The body is " + body_byte)

    print("***")
    print("%s %s Convert header in bin %s" % (Color.BOLD, Color.RED, Color.END))
    # header_bin needs to contain 16 bits (or 2 bytes)
    header_bin = convert_byte_to_bin(header_byte).zfill(16)
    print("Header in binary is %s" % header_bin)

    print("***")
    print("%s %s Extract the id and the message size's size in binary %s" % (Color.BOLD, Color.RED, Color.END))
    id_bin = header_bin[:14]
    message_size_size_bin = header_bin[14:]
    print("The id in binary is %s" % id_bin)
    print("The message size's size in binary is " + message_size_size_bin)

    print("***")
    print("%s %s Convert the id and the message size's size from binary to int %s" % (Color.BOLD, Color.RED, Color.END))
    id_ = convert_bin_to_int(id_bin)
    action = find_action(id_)
    print("The id is %s which corresponds to the %s %s %s action " % (id_, Color.BOLD, action, Color.END))
    message_size_size = convert_bin_to_int(message_size_size_bin)
    print("The message size's is onto %s byte(s)" % message_size_size)

    print("***")
    print("%s %s Break the body into the size of the message and the packet's data %s" % (Color.BOLD,
                                                                                          Color.RED,
                                                                                          Color.END))

    if message_size_size != 0:
        message_size_byte = ':'.join(body_byte.split(":")[:message_size_size])
        message_size = convert_byte_to_int(message_size_byte)

        print("The message occupies %s bytes" % message_size)

    else:
        print("The message does not contain any data")

    packet_data_byte = ':'.join(body_byte.split(":")[message_size_size:])
    print("The packet data is %s" % packet_data_byte)

    return id_, packet_data_byte


class Packet:
    def __init__(self, packet_payload):
        self.payload = packet_payload
        print("Payload is ", self.payload)

        # self.header => split_payload
        # self.body => split_payload

        # self.
        self.header = self.get_header()
        print("Header is ", self.header)
        self.bin_header = self.get_bin_header()
        print("Header in binary (16 bits) is", self.bin_header)
        self.id = self.get_id()
        print("ID is ", self.id)
        self.size_of_size = self.get_size_of_size()
        print("Size of size is ", self.size_of_size)
        self.size_packet = self.get_size_packet()
        print("Size of the packet is ", self.size_packet)
        self.size_message = self.get_size_message()
        print("Size of the message is ", self.size_message)

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
        return str(''.join(self.payload.split(":")[2: 2 + self.size_of_size]))

    def get_size_message(self):
        return int(self.size_packet, base=16)
