from scapy.all import PcapReader, Raw, sniff
from objects.message import Packet
import asyncio


async def sniff_packets(
        prn=None,
        offline=None,
        *args,
        **kwargs
):
    if offline is not None:
        with PcapReader(offline) as pcap_reader:
            print("Reading pcap file...")
            for pa in pcap_reader:
                await on_packet_received(pa)
            print("Finished reading the pcap file...")

    sniffer = sniff(prn=prn, *args, **kwargs)

    return sniffer


async def on_packet_received(packet):
    await on_receive(packet)


def on_receive(pa):
    print("Packet received --- launching the interpretation...")
    message = Packet(pa)
    message.launch_read()

    if getattr(message, "protocol_name") and\
            message.protocol_name == "ExchangeTypesItemsExchangerDescriptionForUserMessage":
        message.push_pg()


async def launch_sniff(action, offline=None):
    print("[*] Start sniffing...")

    iface = "en0"
    filter_options = "tcp port 5555"

    if offline:
        sniffer = await sniff_packets(iface=iface, filter=filter_options, prn=action,
                                      lfilter=lambda p: p.haslayer(Raw), offline=offline
                                      )

        for packet in sniffer:
            on_receive(packet)

    else:
        sniffer = await sniff_packets(iface=iface, filter=filter_options, prn=action, lfilter=lambda p: p.haslayer(Raw))

        sniffer.start()
        await asyncio.sleep(10)
        sniffer.stop()


if __name__ == "__main__":
    asyncio.run(launch_sniff(action=on_receive,
                             # offline="data/captured_packets.pcap"
                             )
                )
