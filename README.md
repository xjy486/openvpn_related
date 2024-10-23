# openvpn_related
openvpn is open的部分代码复现，不少代码是拷的别的同学的。   
仅模拟实现了opcode fingerprint和ack fingerprint    

notes:  

scapy在linux和windows上的用法有点区别，
在linux下访问一个数据包的payload：`bytes(packet[TCP].payload)`  
在windows下访问一个数据包的payload:`pkt[Raw].load.hex()`
