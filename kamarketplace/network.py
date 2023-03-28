from scapy.all import PcapReader, Raw, conf
from scapy import plist
from scapy.data import ETH_P_ALL, MTU
from objects.message import Packet
import threading
from select import select


class PacketBuffer:
    def __init__(self):
        self.buffer = []

    def add_packet(self, packet):
        self.buffer.append(packet)

    def flush(self):
        packets = self.buffer
        self.buffer = []
        return packets


buf = PacketBuffer()


def sniff_packets(prn=None, offline=None,
                  refresh=0.1, lfilter=None, store=False,
                  stop_event=None, *args, **kwargs):

    if offline is None:
        L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *args, **kwargs)
    else:
        s = PcapReader(offline)

    read_allowed_exceptions = EOFError

    def _select(sockets):
        try:
            return select(sockets, [], [], refresh)[0]
        except OSError as exc:
            # Catch 'Interrupted system call' errors
            if exc.errno == errno.EINTR:
                return []
            raise

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            sel = _select([s])
            if s in sel:
                try:
                    p = s.recv(MTU)
                except read_allowed_exceptions:
                    continue
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    buf.add_packet(p)
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

    return buf.flush()

    # if offline is not None:
    #     with PcapReader(offline) as pcap_reader:
    #         print("Reading pcap file...")
    #         for pa in pcap_reader:
    #             await on_packet_received(pa)
    #         print("Finished reading the pcap file...")
    #
    # else:
    #     return sniff(prn=prn, *args, **kwargs)


def on_packet_received(packet):
    """
    Callback function to be called for each packet received.

    Args:
        packet (scapy.packet.Packet): The packet received.
    """
    on_receive(packet)


def on_receive(pa):
    """
    Processes a packet received.

    Args:
        pa (scapy.packet.Packet): The packet to process.
    """
    print("Packet received --- launching the interpretation...")
    message = Packet(pa)
    message.launch_read()

    if getattr(message, "protocol_name") and \
            message.protocol_name == "ExchangeTypesItemsExchangerDescriptionForUserMessage":
        message.push_pg()


def launch_sniff(action, offline=None):
    """
    Launches a packet sniffer.

    Args:
        action (function): Callback function to be called for each packet received.
        offline (str): Path to a pcap file to read packets from. Defaults to None.
    """
    print("[*] Start sniffing...")

    iface = "en0"
    filter_options = "tcp port 5555"

    def _sniff(stop_event):
        if offline:
            sniff_packets(
                filter="tcp port 5555",
                lfilter=lambda p: p.haslayer(Raw),
                stop_event=stop_event,
                prn=lambda p: on_receive(p),
                offline=offline,
            )
        else:
            sniff_packets(
                filter="tcp port 5555",
                lfilter=lambda p: p.haslayer(Raw),
                stop_event=stop_event,
                prn=lambda p: on_receive(p),
            )

    e = threading.Event()
    t = threading.Thread(target=_sniff, args=(e,))
    t.start()

    def stop():
        e.set()

    return stop

        # if offline:
        #     sniffer = await sniff_packets(
        #         iface=iface,
        #         filter=filter_options,
        #         prn=action,
        #         lfilter=lambda p: p.haslayer(Raw),
        #         offline=offline
        #     )
        #
        #     for packet in sniffer:
        #         on_receive(packet)
        #
        # else:
        #     sniffer = await sniff_packets(
        #         iface=iface,
        #         filter=filter_options,
        #         prn=action,
        #         lfilter=lambda p: p.haslayer(Raw)
        #     )
        #
        # sniffer.start()
        # sniffer.stop()


if __name__ == "__main__":
    launch_sniff(action=on_receive,
                 offline="data/captured_packets.pcap"
    )
