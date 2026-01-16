import json
import os
import threading
from collections import defaultdict
import Evtx.Evtx as evtx  # pip install python-evtx
import re
from tqdm import tqdm


# 定义一个线程类
class FileThread(threading.Thread):
    def __init__(self, filepath, filename,save_directory_path):
        threading.Thread.__init__(self)
        self.filepath = filepath
        self.filename = filename
        self.save_directory_path = save_directory_path
    def run(self):
        # 在这里处理读取的数据# 入参：日志文件的路径，文件名称
        # print(self.filepath)
        parse_windows_log_line(self.filepath, self.filename,self.save_directory_path)

# 处理日志函数
def parse_windows_log_line(log_filepath,log_filename,save_directory_path):
    ips = []  # 存储所有的IP信息，使用set避免重复
    ip_infos = defaultdict(set) # 存储除了IP以外的信息
    ids = [] #存储id
    id_infos = defaultdict(set)  #存储id以外的信息
    with evtx.Evtx(log_filepath) as log:
        total_records = len(list(log.records())) #获取日志总条数
        with tqdm(total=total_records, desc="Processing") as pbar:
            for record in log.records():
                record_str = str(record.xml())
                # 定义正则表达式，匹配里面IP地址
                event_id=re.findall(r'<EventID Qualifiers="">(.*?)</EventID>', record_str) # 想要提取的标签说明
                event_ip=re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', record_str)
                event_info=record_str.replace("\n", "")
                # 如果需要提取URL等其他信息，可以在这里处理
                # 例如：ip_urls[match].add(extract_url(record_str))
                if len(event_id) != 0:
                    if event_id[0] not in ids:
                        ids.append(event_id[0])
                    id_infos[event_id[0]].add(event_info)
                if len(event_ip) !=0:
                    if event_ip[0] in ips:
                        ips.append(event_ip[0])
                    ip_infos[event_ip[0]].add(event_info)
                pbar.update(1)
    # 保留分析结果
    # 指定想要保存的路径
    with open(os.path.join(save_directory_path,log_filename.replace(".evtx", "_ip_info.json")),'w') as ip_info_log:
        json.dump({k: list(v) for k, v in ip_infos.items()}, ip_info_log, indent=4)
    with open(os.path.join(save_directory_path,log_filename.replace(".evtx", "_id_info.json")),'w') as id_info_log:
        json.dump({k: list(v) for k, v in id_infos.items()}, id_info_log, indent=4)
# 合并所有日志
class ReadThread(threading.Thread):
    def __init__(self, filepath,save_directory_path):
        threading.Thread.__init__(self)
        self.filepath = filepath
        self.save_directory_path = save_directory_path
    def run(self):
        # 在这里处理读取的数据# 入参：日志文件的路径，文件名称
        get_all_ip(self.filepath,self.save_directory_path)
def get_all_ip(filepath,save_directory_path):
    with open(filepath,'r') as log_file:
        log_lines = json.load(log_file)
    for ip, entries in log_lines.items():
        print(ip)
    exit(0)

def get_all_evtx_info(save_directory):
    json_files = []
    all_json_info = defaultdict(list)
    # 获取所有的文件夹中的json文件，这是已经处理过的
    for root, dirs, files in os.walk(save_directory):
        for file in files:
            if file.endswith('ip_info.json'):
                save_directory_path = os.path.join(root, file)
                json_files.append(save_directory_path)
    # 遍历所有的json文件
    for json_file in json_files:
        with open(json_file, 'r') as f:
            json_datas = json.load(f)
        for ip_datas in json_datas:
            # 此时的ip_req_entry是每个ip的每次请求
            for evtx_data in json_datas[ip_datas]:
                # 没有去重的，就直接添加到一起
                all_json_info[ip_datas].append(evtx_data)
        # 记录所有的ip_url的路径，合并成一个文件
    all_json = save_directory + "\\all.json"
    with open(all_json, 'w') as f:
        json.dump(all_json_info, f, indent=4)


def read_all_json(save_directory_path):
    # 多线程初始过程
    threads = []
    # 遍历指定文件夹
    for root, dirs, files in os.walk(save_directory_path):
        # 遍历文件夹中的每个文件
        for filename in files:
            if filename.endswith('_info.json'):  # 根据需要筛选文件类型
                # 构建文件的完整路径
                # 拼接得到完整路径，只能是root，可能存在文件嵌套的关系
                filepath = os.path.join(root, filename)
                # 参数入口，绝对路径、日志文件名称、处理保存的路径
                thread = ReadThread(filepath,save_directory_path)
                threads.append(thread)
                thread.start()
    for thread in threads:
        thread.join()

def read_all_evtx_ip_info(save_directory):
    all_ip = []
    all_json = save_directory + "\\all.json"
    with open(all_json, 'r') as f_all_json:
        all_ip_evtx_json =json.load(f_all_json)
    for ip, entries in all_ip_evtx_json.items():
        if ip not in all_ip:
            all_ip.append(ip)
    with open(save_directory + "\\all_ip.txt", 'w') as all_ip_log:
        all_ip_log.write('\n'.join(all_ip))


def main(directory,save_directory_path):
    # 多线程初始过程
    threads = []
    # 遍历指定文件夹
    for root, dirs, files in os.walk(directory):
        # 遍历文件夹中的每个文件
        for filename in files:
            if filename.endswith('.evtx'):  # 根据需要筛选文件类型
                # 构建文件的完整路径
                # 拼接得到完整路径，只能是root，可能存在文件嵌套的关系
                filepath = os.path.join(root, filename)
                # 参数入口，绝对路径、日志文件名称、处理保存的路径
                thread = FileThread(filepath,filename,save_directory_path)
                threads.append(thread)
                thread.start()
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    # 日志文件的实际文件夹路径，修改为当前目录下的Windows/Logs/Logs
    directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Windows', 'Logs', 'Logs')
    # 检查日志路径是否合规函数
    if not os.path.exists(directory):
        print(f"目录不存在: {directory}")
        exit(1)
    # 获取当前脚本的执行路径
    current_file_dir = os.path.dirname(os.path.abspath(__file__))
    save_directory_path = os.path.join(current_file_dir, 'Analysis_Windows') # 设置保存的路径
    if not os.path.exists(save_directory_path):
        os.makedirs(save_directory_path)
    print(f"开始处理Windows日志文件")
    print(f"日志目录: {directory}")
    print(f"结果保存目录: {save_directory_path}")
    main(directory,save_directory_path)  # 多线程入口，处理日志文件
    print("合并所有处理结果...")
    get_all_evtx_info(save_directory_path)     #合并所有的处理结果
    print("提取IP信息...")
    read_all_evtx_ip_info(save_directory_path) # 提取部分想要的结果
    print(f"所有分析任务完成！")
    print(f"分析结果已保存到: {save_directory_path}")
