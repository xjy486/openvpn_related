from scapy.all import *
data_directory = 'datasets1'


# 定义用于ACK过滤器的动态阈值
ack_thresholds = {
    1: (1, 3),  # 第一个bin中的ACK数量应在1到3之间
    2: (2, 5),  # 第二个bin中的ACK数量应在2到5之间
}
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
                raw_payload=pkt[Raw].load.hex()
                first_byte=raw_payload[0:2] #PACK 28
                # first_byte_value=int(first_byte,16)
                if first_byte=='28':
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
                raw_payload=pkt[Raw].load.hex()
                first_byte=raw_payload[4:6] #PACK 28
                # first_byte_value=int(first_byte,16)
                if first_byte=='28':
                    bins[i // bin_size] += 1
                else:
                    bins[i // bin_size] += 0
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
def detect_openvpn_sessions(pcap_files):
    suspicious_flows = []
    
    for pcap_file in pcap_files:
        print("当前正在检测的文件是：" + pcap_file)
        ack_packets = rdpcap(pcap_file)
        if identify_packet_type(ack_packets[0])=="TCP":
            bins = group_into_bins_tcp(ack_packets)
        else:
            bins = group_into_bins_udp(ack_packets)
        suspicious_bool=True #默认为可疑
        for bins_number,bins_count in bins.items():
            # dynamic_ack_threshold返回false，则该流量不符合ack探测规律，if判断成立，suspicious_bool改成false，该流量不可疑
            # bin_number下标从0开始
            if not dynamic_ack_threshold(bins_number+1,bins_count):
                suspicious_bool=False
                break
        if suspicious_bool and bins:
            suspicious_flows.append(pcap_file)

    return suspicious_flows
pcap_files =[os.path.join(data_directory, f) for f in os.listdir(data_directory) if f.endswith('.pcap')]
suspicious_flows = detect_openvpn_sessions(pcap_files)
# 输出结果
if suspicious_flows:
    print("检测到以下文件中存在可疑的OpenVPN流量:")
    for flow in suspicious_flows:
        print(flow)
else:
    print("未检测到可疑的OpenVPN流量。")
