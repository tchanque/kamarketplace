from pprint import pprint
from scapy.all import *
import os
import pickle
import math

import logging
from kamarketplace.logger.formatter import CustomFormatter

from kamarketplace.protocol.read_primitives import Data, DIC_TYPES

from pathlib import Path
import sys
path_root = Path(__file__).parents[2]
sys.path.append(str(path_root))

# """ LOGGER configuration """
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# Not needed at the moment, will be when the logs become too heavy
# logger_file = "./logger/message.log"
# file_handler = logging.FileHandler(logger_file)

handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())

log.addHandler(handler)

# """ End of LOGGER configuration """

sys.path.insert(0, os.path.abspath('..'))
path_to_dump = os.path.join(os.path.dirname(os.getcwd()), 'kamarketplace', 'data/captured_packets.pcap')
packet_dump = PcapWriter(path_to_dump,
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
        self.print()
        self.read_header()

    def dump(self):
        global packet_dump
        self.print()

        log.info("Dumping the packet in %s" % path_to_dump)
        packet_dump.write(self.pa)
        log.info("Dump has succeeded")

    def print(self):
        print(
            "[!] New Packet: {src} -> {dst}".format(
                src=self.ip_layer.src,
                dst=self.ip_layer.dst)
        )

    def read_header(self):
        """
        Extract the protocol name out of the header
        Also, extract the body of the packet, where the information is stored (self.data)

        """
        self.header = Data(bytearray(self.payload))

        # Header of the message - Protocol ID and Size

        header = self.header.read_unsignedshort()
        self.protocol_id = header >> 2
        self.protocol_name = msg_from_id[self.protocol_id]['name']
        len_len = header & 3

        data_length = self.header.read_unsigned_byte(len_len)
        self.data = Data(self.header.read(data_length))

        log.info("Successfully read the header. Protocol name is %s" % self.protocol_name)

    def launch_read(self):
        log.info("Starting packet deserialization")
        while self.data.remaining:
            self.read(type_=self.protocol_name)

        print("The content of the packet is")
        pprint(self.content)
        log.info("Packet deserialization is over")

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

        results.update(self.read_bool_vars(type_['boolVars']))

        for var in type_['vars']:
            print("Reading variable %s from %s" % (var["name"], self.data.remaining))
            if var["optional"]:
                if not self.data.read_byte():
                    continue

            if var['length']:
                func = DIC_TYPES[var['length']]
                length = func(self.data)

                res = list()
                for n in range(length):
                    res.append(self.read(var['type']))

                results[var["name"]] = res

            else:
                results[var["name"]] = self.read(var['type'])

        self.content.update(results)
        print(self.content)
        return results

    def read_bool_vars(self, bool_vars):
        var_values = dict()

        variables_count = len(bool_vars)
        bytes_to_read = math.ceil(variables_count / 8)

        bin_ = format(self.data.read_byte(bytes_to_read),
                      '0%sb' % (bytes_to_read * 8))

        for i in range(0, bytes_to_read + 1):
            n_start = 8 * i
            n_end = 8 * (i + 1)

            b = bin_[n_start: n_end]
            bool_vars = [l['name'] for l in bool_vars[n_start: n_end]]

            i = 1
            for var in bool_vars:
                var_values.update({var: bool(int(b[-i]))})
                print("Updating dictionary")
                i += 1

        return var_values





