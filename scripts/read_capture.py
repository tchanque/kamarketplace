from scapy.all import *


def read(file):
    saved_packets = rdpcap(file)
    for pa in saved_packets:
        print(pa)

    # return packets


if __name__ == "__main__":
    read('../kamarketplace/data/captured_packets.pcap')
