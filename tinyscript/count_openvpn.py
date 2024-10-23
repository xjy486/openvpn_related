# 统计pcap文件中的openvpn流量
import os
import pyshark
from collections import defaultdict
from statistics import mode

# 定义tshark的路径
tshark_path = "D:\\software\\Wireshark\\tshark.exe"
directory = 'dataset'
files = os.listdir(directory)
i=0
for file in files:
    i+=1
    print(i)
    file_path = os.path.join(directory, file)  
    cap=pyshark.FileCapture(file_path,tshark_path=tshark_path,keep_packets=True)
    for pkt in cap:
        if 'OPENVPN' in pkt: 
            print(file)
            break
    cap.close()
