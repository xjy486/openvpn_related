from scapy.all import *
from collections import defaultdict
import threading
import multiprocessing
dog = 0
# 用于保存流数据包的字典
streams = defaultdict(list)

ack_thresholds = {
    1: (1, 3),  # 第一个bin中的ACK数量应在1到3之间
    2: (2, 5),  # 第二个bin中的ACK数量应在2到5之间
}

# 自定义回调函数，用于处理捕获到的数据包
def packet_handler(packet):
    if IP in packet:
        flow_id = tuple()
        if identify_packet_type(packet) == "TCP":
            flow_id = tuple(sorted([(packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport)]))
            streams[flow_id].append(packet)
        elif identify_packet_type(packet) == "UDP":
            flow_id = tuple(sorted([(packet[IP].src, packet[UDP].sport), (packet[IP].dst, packet[UDP].dport)]))
            streams[flow_id].append(packet)
                 
        if len(streams[flow_id]) >= 50:
            thread = threading.Thread(target=detect_openvpn_sessions, args=(streams[flow_id].copy(), flow_id))
            thread.start()
        
    else:
        print("忽略非 IP 数据包：", packet)
           

# 保存流数据包到文件的函数
def save_stream_to_file(flow_id):
    global dog
    dog += 1
    filename = f"{flow_id[0][0]}-{flow_id[1][0]}_{flow_id[0][1]}-{flow_id[1][1]}__{dog}.pcap"
    wrpcap(filename, streams[flow_id])
    print(f"流 {flow_id} 的数据包已保存到 {filename}")
    # 清空该流的数据包
    streams.pop(flow_id, None)

def dynamic_ack_threshold(bin_index, count):
    if bin_index in ack_thresholds:
        min_threshold, max_threshold = ack_thresholds[bin_index]
        return min_threshold <= count <= max_threshold
    elif 3 <= bin_index <= 5:
        return count <= 5
    elif 6 <= bin_index:
        return count <= 1
    return False

# 如果openvpn是以udp传输，那么udp的payload的首字节就是P_ACK标志28(16进制)
def group_into_bins_udp(cap, bin_size=10):
    bins = defaultdict(int)
    for i in range(0, len(cap), bin_size):
        bin_packets = cap[i:i + bin_size]
        for pkt in bin_packets:
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                # str类型
                raw_payload = pkt[Raw].load.hex()
                first_byte = raw_payload[0:2]  # PACK 28
                if first_byte == '28':
                    bins[i // bin_size] += 1
                else:
                    bins[i // bin_size] += 0
        
    return bins

# 如果openvpn是以tcp传输，那么tcp的payload的前两个字节是length,后面一个字节是P_ACK标志28(16进制)
def group_into_bins_tcp(cap, bin_size=10):
    bins = defaultdict(int)
    for i in range(0, len(cap), bin_size):
        bin_packets = cap[i:i + bin_size]
        for pkt in bin_packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                # str类型
                raw_payload = pkt[Raw].load.hex()
                first_byte = raw_payload[4:6]  # PACK 28
                if first_byte == '28':
                    bins[i // bin_size] += 1
                else:
                    bins[i // bin_size] +=0
    
    return bins

# 识别数据包时tcp还是udp
def identify_packet_type(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    else:
        return "Neither TCP nor UDP"

# 识别潜在的OpenVPN会话
def detect_openvpn_sessions(packets, flow_id):
    suspicious_flows = []
    if identify_packet_type(packets[0]) == "TCP":
        bins = group_into_bins_tcp(packets)
    else:
        bins = group_into_bins_udp(packets)
    suspicious_bool = True  # 默认为可疑
    for bins_number, bins_count in bins.items():
        # dynamic_ack_threshold返回false，则该流量不符合ack探测规律，if判断成立，suspicious_bool改成false，该流量不可疑
        # bin_number下标从0开始
        if not dynamic_ack_threshold(bins_number + 1, bins_count):
            suspicious_bool = False
            break
    if suspicious_bool and bins:
        print(f"流 {flow_id} 可能是OpenVPN流量")
        # print(bins)/
        save_stream_to_file(flow_id)
        

if __name__ == "__main__":
    # 开始实时嗅探
    sniff(prn=packet_handler, store=1)