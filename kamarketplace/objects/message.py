from scapy.all import *
import os

cdir = os.getcwd()
pardir = os.path.dirname(cdir)
path = os.path.join(pardir,
                    os.path.join('kamarketplace', 'data/captured_packets.pcap'))

packet_dump = PcapWriter(path,
                         append=True,
                         sync=True)


class Packet:

    def __init__(self, pa):
        self.pa = pa
        self.ip_layer = self.pa.getlayer("IP")

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
        bytes(self.pa["TCP"].payload)

    # def deserialize(self):
