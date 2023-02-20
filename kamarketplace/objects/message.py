from scapy.all import *
import os
import sys
import pickle
from pathlib import Path

from protocol.protocol_reader import read_message, msg_from_id
from protocol.types_reader import Data, DIC_TYPES

sys.setrecursionlimit(10000)

sys.path.insert(0, os.path.abspath('..'))

path = os.path.join(os.path.dirname(os.getcwd()),
                    'kamarketplace', 'data/captured_packets.pcap')

packet_dump = PcapWriter(path,
                         append=True,
                         sync=True)

with (Path(__file__).parent / "protocol.pk").open("rb") as f:
    types = pickle.load(f)
    msg_from_id = pickle.load(f)
    types_from_id = pickle.load(f)
    primitives = pickle.load(f)


class Packet:

    def __init__(self, pa):
        self.pa = pa
        self.ip_layer = self.pa.getlayer("IP")
        self.payload = self.pa.getlayer(Raw).load
        self.protocol_id = None
        self.protocol_name = None
        self.content_to_decode = None
        self.content = {}

        self.read_header()

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

    def read_header(self):
        msg_to_decode = bytearray(self.payload)

        # Header of the message - Protocol ID and Size
        header = msg_to_decode[:2]
        msg_to_decode = msg_to_decode[2:]

        header_int = int.from_bytes(header, byteorder="big")
        self.protocol_id = header_int >> 2
        self.protocol_name = msg_from_id[self.protocol_id]['name']
        len_len = header_int & 3

        length_data = int.from_bytes(msg_to_decode[:len_len], byteorder="big")
        self.content_to_decode = Data(msg_to_decode[len_len:length_data])

        print("The protocol ID is %s" % self.protocol_id)

    def get_content(self, protocol_name=None):
        if protocol_name is None:
            protocol_name = self.protocol_name

        structure = types[protocol_name]

        print("Deserializing %s" % protocol_name)
        print(self.content_to_decode.remaining)
        variables = structure['vars']

        while self.content_to_decode.remaining:

            if not structure['parent'] is None:
                print("The message %s has a parent which is %s" % (protocol_name,
                                                                   structure['parent']))
                # recall the function above
                parent = structure['parent']
                self.get_content(parent)

            for var in variables:
                var_type = var['type']
                var_name = var['name']
                var_length = var['length']
                print(var_name)

                if var_type is False:
                    type_id = self.content_to_decode.read_unsignedshort()
                    type_name = types_from_id[type_id]['name']
                    self.get_content(type_name)

                elif var_type and var_type not in primitives:
                    print("Type %s is complex" % var_type)
                    self.get_content(var_type)

                else:
                    print("Type %s is primitive" % var_type)
                    func = DIC_TYPES[var_type]
                    res = func(self.content_to_decode)
                    self.content[var_name] = res
                    print("Variable %s : %s" % (var_name, res))

            return self.content

        print("*** Finished deserialization of %s ***" % protocol_name)
        return self.content
