from pprint import pprint

from scapy.all import *
import os
import sys
import pickle
from pathlib import Path
import math

from protocol.types_reader import Data, DIC_TYPES

sys.setrecursionlimit(100)

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
        self.header = None
        self.data = None
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
        self.header = Data(bytearray(self.payload))

        # Header of the message - Protocol ID and Size

        header = self.header.read_byte(2)
        self.protocol_id = header >> 2
        self.protocol_name = msg_from_id[self.protocol_id]['name']
        len_len = header & 3

        data_length = self.header.read_unsigned_byte(len_len)
        self.data = Data(self.header.read(data_length))

        print("The protocol name is %s" % self.protocol_name)

    def launch_read(self):
        print("***START DESERIALIZATION***")
        while self.data.remaining:
            self.read(type_=self.protocol_name)

        print("***FINISHED DESERIALIZATION***")

    def read(self, type_=None):
        if type_ is None:
            type_ = self.protocol_name

        # type can be false, in this case we need to read the first unsigned short which corresponds to the type id
        if type_ is False:
            print("Type is False so reading the unsigned short to get the id")
            type_ = types_from_id[self.data.read_unsignedshort()]

        # if type is directly coming from a variable then it is a string
        if isinstance(type_, str):
            if type_ in primitives:
                func = DIC_TYPES[type_]
                return func(self.data)

            # else the type of the variable is complex therefore we look for its structure before continuing
            type_ = types[type_]

        # from this point on, type_ is the structure of a protocol as dict, with keys being name, parent, variables,
        # bool_vars

        if type_['parent']:
            results = self.read(type_['parent'])

        else:
            results = dict()
            self.content["name"] = type_['name']

        for var in type_['vars']:
                if var['length']:
                    func = DIC_TYPES[var['length']]
                    length = func(self.data)

                    res = list()
                    for n in range(length):
                        res.append(self.read(var['type']))

                    results[var["name"]] = res

                else:
                    print("Reading variable %s out of %s" % (var["name"], self.data.remaining))
                    results[var["name"]] = self.read(var['type'])

        if type_['boolVars']:
            results.update(self.read_bool_vars(type_['boolVars']))

        self.content.update(results)
        return results

    def read_bool_vars(self, boolvars):
        var_values = dict()

        variables_count = len(boolvars)
        bytes_to_read = math.ceil(variables_count / 8)

        bin_ = format(self.data.read_byte(bytes_to_read),
                      '0%sb' % (bytes_to_read * 8))

        for i in range(0, bytes_to_read + 1):
            n_start = 8 * i
            n_end = 8 * (i + 1)

            b = bin_[n_start: n_end]
            bool_vars = [l['name'] for l in boolvars[n_start: n_end]]

            i = 1
            for var in bool_vars:
                var_values.update({var: bool(int(b[-i]))})
                print("Updating dictionary")
                i += 1

        return var_values





