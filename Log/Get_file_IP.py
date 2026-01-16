import json
import os
import threading
from collections import defaultdict
import re

def main(directory,save_directory_path):
    ip_json=[]
    all_ip_json_info=defaultdict(set)
    file_paths=[]
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    # 遍历指定文件夹
    for root, dirs, files in os.walk(directory):
        # 遍历文件夹中的每个文件
        for filename in files:
            if filename.endswith('.txt') or filename.endswith('.log') :  # 根据需要筛选文件类型
                # 构建文件的完整路径
                # 拼接得到完整路径，只能是root，可能存在文件嵌套的关系
                filepath = os.path.join(root, filename)
                # 参数入口，绝对路径、日志文件名称、处理保存的路径
                file_paths.append(filepath)
    # 遍历文件
    for file_path in file_paths:
        with open(file_path, 'r',encoding='gb18030',errors = 'ignore') as file:
            file_infos = file.read()
        # 一次性读取整个文件的内容
        file_ip = ip_pattern.findall(file_infos)
        if len(file_ip) !=0:
            if file_ip[0] not in ip_json:
                ip_json.append(file_ip[0])
            all_ip_json_info[file_ip[0]].add(file_path)
        else:
            all_ip_json_info["None_ip"].add(file_path)
    save_filename = os.path.join(save_directory_path, 'Analysis_File_IP_ALL.json')
    get_ip ={k: list(v) for k, v in all_ip_json_info.items()}
    with open(save_filename,'w') as ip_info_log:
        json.dump(get_ip, ip_info_log, indent=4)



if __name__ == '__main__':
    directory = r'C:\Users\Desktop\Redis'  # 日志文件的实际文件夹路径
    # 检查日志路径是否合规函数
    if not os.path.exists(directory):
        print("Directory doesn't exist")
        exit(1)
    # 获取当前脚本的执行路径
    current_file_dir = os.path.dirname(os.path.abspath(__file__))
    save_directory_path = os.path.join(current_file_dir, 'Analysis_File_IP') # 设置保存的路径
    if not os.path.exists(save_directory_path):
        os.makedirs(save_directory_path)
    main(directory,save_directory_path)  # 多线程入口，处理没有日志文件
