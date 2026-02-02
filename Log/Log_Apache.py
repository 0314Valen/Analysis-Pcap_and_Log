import json
import os
import re
import threading
from collections import defaultdict

# 定义一个线程类
class FileThread(threading.Thread):
    def __init__(self, filepath,filename,save_directory):
        threading.Thread.__init__(self)
        self.filepath = filepath
        self.filename = filename
        self.save_directory = save_directory
    def run(self):
        print(f"正在处理文件: {self.filename}")
        print(f"文件路径: {self.filepath}")
        # 给每个日志创建对应的文件夹
        save_log = os.path.join(self.save_directory, self.filename)
        if not os.path.exists(save_log):
            os.makedirs(save_log, exist_ok=True)
        # 在这里处理读取的数据
        with open(self.filepath, 'r', encoding='utf-8') as file:
            data = file.readlines()
        # 入参：日志文件的路径，读取的数据
        ips, ip_urls = parse_apache_log_line(self.filepath, data)
        # 单个日志中所有的IP访问的URL
        ip_urls_path = os.path.join(save_log, 'ip_urls.json')
        with open(ip_urls_path, 'w', encoding='utf-8') as one_ip_url_file:
            # 转成json来处理
            normal_dict = {k: list(v) for k, v in ip_urls.items()}
            json.dump(normal_dict, one_ip_url_file, indent=4, ensure_ascii=False)
        print(f"文件 {self.filename} 处理完成")

# 处理所有的json文件并且输出合并之后的结果
def get_all_url(save_directory):
    json_files = []
    all_json_info = defaultdict(list)
    # 获取所有的文件夹中的json文件，这是已经处理过的
    for root, dirs, files in os.walk(save_directory):
        for dir in dirs:
            if dir.endswith('.log'):
                save_directory_path = os.path.join(root, dir)
                for sub_root, sub_dirs, sub_files in os.walk(save_directory_path):
                    for sub_file in sub_files:
                        if sub_file.endswith('.json'):
                            json_files.append(os.path.join(sub_root, sub_file))
    # 遍历所有的json文件
    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        for ip_data in json_data:
            # 此时的ip_req_entry是每个ip的每次请求
            for ip_req_entry in json_data[ip_data]:
                # 没有去重的，就直接添加到一起
                all_json_info[ip_data].append(ip_req_entry)
    # 记录所有的ip_url的路径，合并成一个文件
    all_json_path = os.path.join(save_directory, 'all.json')
    with open(all_json_path, 'w', encoding='utf-8') as f:
        json.dump(all_json_info, f, indent=4, ensure_ascii=False)
    print(f"所有JSON文件合并完成，结果保存到: {all_json_path}")

# 处理所有的json文件，输出404和IP统计
def read_all_log_info(save_directory):
    get_404_log = defaultdict(list)
    all_ip = []
    request_count = defaultdict(int)  # 统计每个IP的请求次数
    status_count = defaultdict(int)  # 统计状态码分布
    file_downloads = defaultdict(int)  # 统计文件下载次数
    
    # 记录所有的ip_url的路径
    all_json_path = os.path.join(save_directory, 'all.json')
    with open(all_json_path, 'r', encoding='utf-8') as alllog:
        all_json_log = json.load(alllog)
    
    for ip, entries in all_json_log.items():
        # 去重获取信息
        if ip not in all_ip:
            all_ip.append(ip)
        
        # 统计该IP的请求次数
        request_count[ip] = len(entries)
        
        # 提取想要处理的状态码
        for entry in entries:
            # 分析日志条目
            if "--checkloginfo--" in entry:
                parts = entry.split("--checkloginfo--")
                if len(parts) >= 4:
                    status_code = parts[2]
                    request_url = parts[1]
                    
                    # 统计状态码
                    status_count[status_code] += 1
                    
                    # 检查是否是404错误
                    if status_code == "404":
                        get_404_log[ip].append(entry)
                    
                    # 检查是否是文件下载请求
                    if "?dl" in request_url or ".exe" in request_url or ".zip" in request_url:
                        file_downloads[request_url] += 1
    
    # 保存404错误日志
    all_404_path = os.path.join(save_directory, 'all_404.json')
    with open(all_404_path, 'w', encoding='utf-8') as all_404_log:
        json.dump(dict(get_404_log), all_404_log, indent=4, ensure_ascii=False)
    
    # 保存IP列表
    all_ip_path = os.path.join(save_directory, 'all_ip.txt')
    with open(all_ip_path, 'w', encoding='utf-8') as all_ip_log:
        all_ip_log.write('\n'.join(all_ip))
    
    # 保存请求次数统计
    request_count_path = os.path.join(save_directory, 'request_count.json')
    with open(request_count_path, 'w', encoding='utf-8') as f:
        json.dump(dict(request_count), f, indent=4, ensure_ascii=False)
    
    # 保存状态码统计
    status_count_path = os.path.join(save_directory, 'status_count.json')
    with open(status_count_path, 'w', encoding='utf-8') as f:
        json.dump(dict(status_count), f, indent=4, ensure_ascii=False)
    
    # 保存文件下载统计
    file_downloads_path = os.path.join(save_directory, 'file_downloads.json')
    with open(file_downloads_path, 'w', encoding='utf-8') as f:
        json.dump(dict(file_downloads), f, indent=4, ensure_ascii=False)
    
    # 保存统计报告
    report_path = os.path.join(save_directory, 'analysis_report.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("Apache日志分析报告\n")
        f.write("=" * 30 + "\n\n")
        f.write(f"1. 总IP数量: {len(all_ip)}\n")
        f.write(f"2. 总请求数量: {sum(request_count.values())}\n\n")
        
        f.write("3. 状态码分布:\n")
        for status, count in sorted(status_count.items()):
            f.write(f"   {status}: {count}次\n")
        f.write("\n")
        
        f.write("4. 请求次数最多的IP:\n")
        for ip, count in sorted(request_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            f.write(f"   {ip}: {count}次\n")
        f.write("\n")
        
        f.write("5. 404错误统计:\n")
        f.write(f"   总404错误数: {sum(len(entries) for entries in get_404_log.values())}\n")
        f.write(f"   产生404错误的IP数: {len(get_404_log)}\n\n")
        
        f.write("6. 文件下载统计:\n")
        for url, count in sorted(file_downloads.items(), key=lambda x: x[1], reverse=True)[:10]:
            f.write(f"   {url}: {count}次\n")
    
    print(f"日志分析完成，生成以下文件:")
    print(f"  - {all_404_path}")
    print(f"  - {all_ip_path}")
    print(f"  - {request_count_path}")
    print(f"  - {status_count_path}")
    print(f"  - {file_downloads_path}")
    print(f"  - {report_path}")

# 处理日志函数
def parse_apache_log_line(filepath, log_data):
    ips = []
    # 定义分割符号
    special_char = "--checkloginfo--"
    ip_urls = defaultdict(set)  # 存储除了IP以外的信息
    # 定义正则表达式，匹配标准Apache访问日志格式，支持IPv6地址、IPv4地址、主机名或域名，支持包含或不包含用户名，同时支持包含和不包含请求体的情况
    log_pattern = r'([\w:.\-]+) - ([^\[]+) \[(.*?)\] "(.*?)" (\d+) (\d+|-)(?: "(.*?)")?$'

    for logline in log_data:
        logline = logline.strip()
        if not logline:
            continue
        
        match = re.match(log_pattern, logline)
        if match:
            ip_address = match.group(1)
            username = match.group(2).strip()  # 提取用户名并去除两端空白
            request_time = match.group(3)
            request_method_url = match.group(4)
            status_code = match.group(5)
            response_size = match.group(6)
            request_body = match.group(7) if match.lastindex >= 7 else ""
            
            # 构建URL信息
            url_info = f"[{request_time}]{special_char}{request_method_url}{special_char}{status_code}{special_char}{response_size}{special_char}{request_body}"
            
            if ip_address not in ip_urls:
                ips.append(ip_address)
            ip_urls[ip_address].add(url_info)
        else:
            print(f"格式错误的日志行: {logline}")
            # 不再直接退出，而是继续处理其他行
    return ips, ip_urls

# 主函数
def main(directory, save_directory):
    # 多线程初始过程
    threads = []
    # 遍历指定文件夹
    for root, dirs, files in os.walk(directory):
        # 排除保存目录，避免处理已经生成的结果文件
        if root == save_directory:
            continue
        
        # 遍历文件夹中的每个文件
        for filename in files:
            # 支持.log文件和.txt文件
            if filename.endswith('.log') or filename.endswith('.txt'):
                # 构建文件的完整路径
                filepath = os.path.join(root, filename)
                # 参数入口，绝对路径、日志文件名称、处理保存的路径
                thread = FileThread(filepath, filename, save_directory)
                threads.append(thread)
                thread.start()
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    print("所有日志文件处理完成")

# 程序入口
if __name__ == '__main__':
    # 日志文件的实际文件夹路径，当前目录下的access-2024-06-25.log
    directory = r"D:\Programming\python\pythonproject\study\forensics\check_log\Apache\logs"  # 当前脚本所在目录
    
    # 保留处理结果的路径，默认保存在脚本运行的Analysis_Apache文件夹中，自动创建
    save_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Analysis_Apache')
    
    # 检查日志路径是否合规
    if not os.path.exists(directory):
        print(f"目录不存在: {directory}")
        exit(1)
    
    # 创建保存目录
    if not os.path.exists(save_directory):
        os.makedirs(save_directory, exist_ok=True)
    
    print(f"开始处理日志文件")
    print(f"日志目录: {directory}")
    print(f"结果保存目录: {save_directory}")
    
    main(directory, save_directory)  # 多线程入口，处理日志文件
    get_all_url(save_directory)     # 合并所有的处理结果
    read_all_log_info(save_directory) # 提取分析结果
    
    print("\n所有分析任务完成！")
    print(f"分析结果已保存到: {save_directory}")
