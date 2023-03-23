from scapy.all import PcapReader, Raw, sniff
from objects.message import Packet


def sniff_(
        prn=None,
        offline=None,
        # lfilter=None,
        # store=False,
        # stop_event=None,
        # refresh=0.1,
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
            # count=10,
            *args, **kwargs)


def on_receive(pa):
    # do something when receive the packet
    print("Packet received --- launching the interpretation")
    message = Packet(pa)
    message.print()
    message.launch_read()
    try:
        getattr(message, "protocol_name") & getattr(message, "content")
        if message.protocol_name == "BidExchangerObjectInfo":
            print("Inserting the resources prices in the Database")
            message.push_pg()

    except AttributeError:
        print("Protocol not defined")


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
        offline="data/captured_packets.pcap"
                 )
