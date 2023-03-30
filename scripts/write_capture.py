from kamarketplace.objects.msg import Packet
from kamarketplace.network import launch_sniff


def write(pa):
    # global packet_dump
    msg = Packet(pa)
    msg.dump()


if __name__ == "__main__":
    launch_sniff(action=write)
