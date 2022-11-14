import pyshark

capture = pyshark.LiveCapture(interface='en0', bpf_filter='tcp port 5555 and len > 66')
capture.sniff(timeout=5)

print("[DEBUG] {} paquets reçus".format(len(capture)))
for packet in capture:
    print(packet)

dns_1 = capture[0]
print(dns_1)
