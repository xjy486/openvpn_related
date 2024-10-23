# 删除小于一定大小的pcap文件
import os

directory = 'dataset'
files = os.listdir(directory)

for file in files:
    file_path = os.path.join(directory, file)
    if os.path.isfile(file_path):
        file_size = os.path.getsize(file_path)
        if file_size < 4 * 1024:  # 4KB = 4 * 1024 bytes
            os.remove(file_path)
            print(f"Deleted {file_path}")
print(files)
