from scapy.all import PcapReader, Raw, sniff, conf
from objects.message import Packet
import asyncio


def sniff_(
        prn=None,
        offline=None,
        # lfilter=None,
        # store=False,
        # stop_event=None,
        refresh=False,
        *args,
        **kwargs
):
    if offline is not None:
        p = PcapReader(offline)
        print("Read the pcap")
        for pa in p:
            prn(pa)
    else:
        sniff(
            prn=prn,
            # refresh=refresh,
            # L3socket=conf.L3socket,
            # count=0,
            *args, **kwargs)


def on_receive(pa):
    print("Packet received --- launching the interpretation")
    message = Packet(pa)
    message.launch_read()

    if getattr(message, "protocol_name") and\
            message.protocol_name == "ExchangeTypesItemsExchangerDescriptionForUserMessage":
        message.push_pg()


interface = "en0"


def launch_sniff(action, offline=None):
    print("[*] Start sniffing...")

    if offline:
        # Read a pcap file
        sniff_(iface=interface,
               filter="tcp port 5555",
               prn=action,
               lfilter=lambda p: p.haslayer(Raw),
               offline=offline,
               )

    else:
        # Sniff live
        sniff_(iface=interface,
               filter="tcp port 5555",
               prn=action,
               lfilter=lambda p: p.haslayer(Raw),
               )


if __name__ == "__main__":
    launch_sniff(
        action=on_receive,
        # offline="data/captured_packets.pcap"
                 )
