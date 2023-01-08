import pyshark
import pandas as pd
import nest_asyncio
nest_asyncio.apply()


def sniff_packets(time):
    capture = pyshark.LiveCapture(interface='en0', bpf_filter='tcp port 5555 and len > 66')
    capture.sniff_(timeout=time)
    return capture


def aggregate_in_list(captured):
    list_packets_data = []

    print("[DEBUG] {} packets received".format(len(captured)))
    for packet in captured[:33]:
        try:
            print("Inserting the data in the list")
            list_packets_data.append(packet.tcp.payload)
        except AttributeError:
            print("No data in this packet")
            pass

    return list_packets_data


def export_packets(packets_, path='./data/', name='example_packets.csv'):
    pd.DataFrame(packets_, columns=['data']).to_csv(
        "%s%s" % (path, name),
        index=False
    )


if __name__ == "__main__":
    print("Starting sniffing")
    # start sniffing the packets
    packets = sniff_packets(time=10)
    packets_list = aggregate_in_list(packets)

    export_packets(packets_list)

    print("End of sniffing")
