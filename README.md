# openvpn_related

openvpn is open 的部分代码复现，不少代码是参考的别的同学的。  
仅模拟实现了 opcode fingerprint 和 ack fingerprint

## notes:

scapy 在 linux 和 windows 上的用法有点区别，
在 linux 下访问一个数据包的 payload：`bytes(packet[TCP].payload)`
在 windows 下访问一个数据包的 payload:`pkt[Raw].load.hex()`

`ack_fp_realtime.py`有一点不足，不能处理 IPV6 的流量，需要继续改进。

```
# 找到含有openvpn流量的pcap文件，并输出文件名
tinyscript/count_openvpn.py
# 删除小于4kb大小的pcap文件
tinyscript/delete_pcap.py
# 识别数据包的传输层协议是tcp还是udp，还是都是不是
tinyscript/identify_udp_tcp.py
```
