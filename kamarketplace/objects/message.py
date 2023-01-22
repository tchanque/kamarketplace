from scapy.all import *
import os
from bitstring import BitArray
import pickle
from .protocol_load import read_message


cdir = os.getcwd()
pardir = os.path.dirname(cdir)
path = os.path.join(pardir,
                    os.path.join('kamarketplace', 'data/captured_packets.pcap'))

packet_dump = PcapWriter(path,
                         append=True,
                         sync=True)

with open(os.path.dirname(os.path.abspath("__file__")) + "/protocol.pk", mode="rb") as f:
    types = pickle.load(f)
    msg_from_id = pickle.load(f)
    types_from_id = pickle.load(f)
    primitives = pickle.load(f)


class Packet:

    def __init__(self, pa):
        self.pa = pa
        self.ip_layer = self.pa.getlayer("IP")
        self.payload = self.read()
        print(self.payload)

    def dump(self):
        global packet_dump
        self.print()

        packet_dump.write(self.pa)

        print("Dumping the packet in data/captured_packets.pcap")

    def print(self):
        print(
            "[!] New Packet: {src} -> {dst}".format(
                src=self.ip_layer.src,
                dst=self.ip_layer.dst)
        )

    def read(self):
        return bytes(self.pa["TCP"].payload)

    def deserialize(self):
        # read the header
        print("Reading the first byte")
        remaining_data = self.payload

        header = remaining_data[:2]
        remaining_data = remaining_data[2:]

        bits = BitArray(header).bin
        id_protocol = int(bits[:14], 2)
        protocol_name = msg_from_id[id_protocol]['name']

        size = int(bits[-2:], 2)
        print("The protocol ID is %s and the action is %s" % (id_protocol, protocol_name))
        # print("The size is %s" % size)

        message_size = remaining_data[:size]
        remaining_data = remaining_data[:size]
        # print(message_size)

        # need to deserialize now
        msg_structure = msg_from_id[id_protocol]
        # print(msg_structure)
        # variables_structure = msg_structure['vars']
        #
        # for var_str in variables_structure:
        #     print(var_str)
        #     name = var_str['name']
        #     length = var_str['length']
        #     type = var_str['type']
        #     optional = var_str['optional']
        #
        #     if type and type not in primitives:
        #         print("Type %s has its own structure" % type)
        #         type_structure = types[type]
        #         for
        #
        #     else:
        #         # read_primitive_type()

        read_message(remaining_data, id_protocol)













