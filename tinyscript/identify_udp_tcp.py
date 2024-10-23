# 判断数据包是tcp还是udp
from scapy.all import *
cap=rdpcap('openvpn_test_example.pcap')
def identify_packet_type(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    else:
        return "Neither TCP nor UDP"

# 捕获一个数据包进行测试
packet=cap[0]
packet_type = identify_packet_type(packet)
print(f"The packet is of type: {packet_type}")
