import os
import re

def read_ip_info(file_paths):
    # 定义正则表达式匹配IP地址
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    # 存储找到的IP信息
    ip_info = {}

    # 遍历文件路径列表
    for file_path in file_paths:
        try:
            # 打开并读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # 查找文件中的IP地址
                ips = ip_pattern.findall(content)
                if ips:
                    ip_info[file_path] = ips
        except Exception as e:
            print(f"读取文件{file_path}时出错：{e}")

    return ip_info

def check_duplicate_ips(ip_info):
    # 存储所有IP地址
    all_ips = []
    # 存储重复的IP地址
    duplicate_ips = []

    # 收集所有IP地址
    for ips in ip_info.values():
        all_ips.extend(ips)
    print(all_ips)

    # 检查重复的IP地址
    for ip in set(all_ips):
        if all_ips.count(ip) > 0:
            duplicate_ips.append(ip)

    return duplicate_ips
# Analysis_Apache_all_ip=r"D:\Programming\python\pythonproject\study\forensics\check_log\Analysis_Apache\all_ip.txt"
# Analysis_Windows_all_ip=r"D:\Programming\python\pythonproject\study\forensics\check_log\Analysis_Windows\all_ip.txt"
hfs_ips=r"D:\Programming\python\pythonproject\study\forensics\check_log\Redis\access.log"
# 指定四个文件的路径
# file_paths = [Analysis_Apache_all_ip,Analysis_Windows_all_ip,hfs_ips]
file_paths = [hfs_ips]
ip_info = read_ip_info(file_paths)

# 检查重复的IP地址
duplicate_ips = check_duplicate_ips(ip_info)

# 打印结果
if duplicate_ips:
    print("发现重复的IP地址：")
    for ip in duplicate_ips:
        print(ip)
else:
    print("没有发现重复的IP地址。")