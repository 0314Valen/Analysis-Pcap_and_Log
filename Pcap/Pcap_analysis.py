import json
import os
import subprocess
from urllib.parse import unquote, urlparse


class CapInfo():
    def __init__(self,debug=False):
        """
        初始化分析器
        """
        self.outfile = None
        self.debug = debug
        # 用于结构化保存分析结果
        self.analysis_results = {
            "ip_addresses": {},  # 提取的IP地址集合
            "domains": {},  # 提取的域名集合
            "urls": {}, # 提取的URL集合
            "http_all_data": {},  # 结构化的HTTP请求响应数据
            # 非结构化数据，仅作展示使用
            "basic_info": "",  # 流量包基本信息
            "protocols": "",  # 流量包里面的协议分布信息
        }
        self.rules="rules/attacks.json"

    # ==================== 工具函数 ====================
    def check_file(self, input_file):
        # 验证输入文件是否存在
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"输入文件不存在: {input_file}")
        # 验证输入文件是否是 pcap 或 pcapng 文件
        if not (input_file.endswith('.pcap') or input_file.endswith('.pcapng')):
            raise ValueError(f"输入文件必须是 pcap 或 pcapng 格式: {input_file}")
        self.outfile = input_file.replace('.pcapng', '.json').replace('.pcap', '.json') # 处理结果保存到的文件



    def jsonstr_to_file(self,content):
        with open(self.outfile, 'w', encoding='utf-8') as f:
            json.dump(content, f, ensure_ascii=False, indent=2)

    def run_tshark(self, desc, cmd):
        """执行tshark命令并返回输出结果。
        参数：
            desc (str): 命令描述，用于日志和输出显示
            cmd (str): 要执行的tshark命令
        返回：
            str: 命令执行的输出结果，如果命令失败则包含错误信息
        """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout if result.returncode == 0 else f"{desc}\t执行命令\n{cmd}\t执行失败提示: {result.stderr}"
        run_outfile = self.outfile.replace('.json', '_runtime.log')
        # 保存命令运行记录
        reponse=f"-----------{desc}-----------\n命令:\n{cmd}\n执行命令结果:\n{result.stderr}"+output+"-------------------------------------------------------"
        with open(run_outfile, 'w', encoding='utf-8') as f:
            f.write(reponse)
        return reponse

    def _increment_counter(self, category: str, key: str, extra_fields=None):
        """
        统一增加指定分类中某个键的计数器（sum 字段）

        Args:
            category (str): 如 "ip_addresses", "urls", "domains"
            key (str): 要统计的具体值，如 IP 地址或 URL

        """
        # 确保该分类存在，并是一个字典
        # 如果你以后想扩展功能，比如记录“首次出现时间”、“数据包数量”等，可以这样设计：
        if category not in self.analysis_results:
            self.analysis_results[category] = {}

        entry = self.analysis_results[category].setdefault(key, {"sum": 0})
        entry["sum"] += 1

    def decode_hex(self, hex_string: str) -> str:
        """
        解码十六进制字符串并进行URL解码。
        参数：
            hex_string (str): 要解码的十六进制字符串
        返回：
            str: 解码后的字符串
        """
        try:
            # 尝试十六进制解码
            data = bytes.fromhex(hex_string)
            result = data.decode("utf-8", errors="ignore")
        except ValueError:
            # 如果不是合法的十六进制，就直接当普通字符串处理
            result = hex_string  # 再做一次 URL 解码
        result = unquote(result)
        return result

    def parse_http_headers(self, header_line: str) -> dict:
        """解析HTTP头信息，返回结构化的字典"""
        headers = {}
        if not header_line:
            return headers
        # 处理响应头，格式如: Server: nginx/1.15.11\r\n,Date: Wed, 19 Apr 2023 13:48:01 GMT\r\n,...
        # 首先按\r\n, 拆分
        header_pairs = header_line.split('\\r\\n,')

        for pair in header_pairs:
            if ':' in pair:
                # 分割键值对
                key, value = pair.split(':', 1)
                # 去除首尾空格
                key = key.strip()
                value = value.strip()
                # 去除值末尾可能的\r\n
                value = value.rstrip('\\r\\n')
                if key:
                    headers[key] = value
        return headers



    def parse_tshark_output(self,output):
        """解析tshark命令输出并将结果结构化保存到分析结果中。
        参数：
            desc (str): 命令描述，用于识别输出类型
            output (str): tshark命令的输出结果
        """
        # 解析HTTP请求URL请求方法和状态码及数据
        # 临时字典，用于存储每个流的请求信息
        stream_requests = {}
        http_request_detail, http_response_detail, http_request_lines, http_response_lines, http_request_data, http_response_data, request_host, request_method = {}, {}, "", "", "", "", "", ""
        for line in output.strip().split('\n'):
            if line:
                parts = line.split('\t')
                # 确保字段数能够匹配上，字段信息在tshark中,
                if len(parts) == 16:
                    frame_number, frame_time, tcp_stream, ip_src, ip_dst, tcp_srcport, tcp_dstport, http_request_method, http_request_full_uri, http_host, http_file_data, http_response_code, http_response_line, http_request_line, http_request_version, http_response_version = parts[:16]
                    # 固定基本数据处理
                    # 源IP和目的IP统计
                    self._increment_counter("ip_addresses", ip_src)
                    self._increment_counter("ip_addresses", ip_dst)
                    # URL 统计
                    if http_request_full_uri and http_request_version: # 只取请求
                        self._increment_counter("urls", http_request_full_uri)
                        # 提取域名并统计
                        try:
                            domain = urlparse(http_request_full_uri).netloc
                            if domain:  # 防止空 netloc
                                self._increment_counter("domains", domain)
                        except Exception as e:
                            pass
                    # 模糊区分一下是请求还是响应，根据请求或响应的版本来判断
                    # 处理file_data，请求和响应的字段信息并且转换成明文的
                    if http_request_version:
                        http_request_data = self.decode_hex(http_file_data)
                        http_request_lines = self.parse_http_headers(http_request_line)
                        request_host = http_host
                        request_method = http_request_method
                    else:
                        http_response_data = self.decode_hex(http_file_data)
                        http_response_lines = self.parse_http_headers(http_response_line)

                    if http_request_version:  # 有request_version表示这是一个请求
                        # """这是一个请求字段"""
                        http_request_detail = {
                            "number": frame_number,
                            "ip_src": ip_src,
                            "ip_dst": ip_dst,
                            "tcp_srcport": tcp_srcport,
                            "tcp_dstport": tcp_dstport,
                            "host": request_host,
                            "request_method": request_method,
                            "request_full_uri": http_request_full_uri,
                            "request_data": http_request_data,
                            "request_line": http_request_lines,
                            "request_version": http_request_version,
                            "frame_time": frame_time,
                        }
                    else:
                        # 有response_version表示这是一个响应
                        # """这是一个响应字段"""
                        http_response_detail = {
                            "number": frame_number,
                            "ip_src": ip_src,
                            "ip_dst": ip_dst,
                            "tcp_srcport": tcp_srcport,
                            "tcp_dstport": tcp_dstport,
                            "host": request_host,
                            "request_method": request_method,
                            "request_full_uri": http_request_full_uri,
                            "request_data": http_request_data,
                            "request_line": http_request_lines,
                            "frame_time": frame_time,
                            "response_data": http_response_data,
                            "response_code": http_response_code,
                            "response_line": http_response_lines,
                            "response_version": http_response_version,
                        }
                    # 构建基本的集合
                    # 将请求添加到对应的tcp_stream下
                    if tcp_stream not in stream_requests:
                        stream_requests[tcp_stream] = {
                            "requests": [],
                            "responses": []
                        }
                    # 检查是请求还是响应
                    if http_request_version:  # 有request_version表示这是一个请求
                        stream_requests[tcp_stream]["requests"].append(http_request_detail)
                    elif http_response_version:  # 有response_version表示这是一个响应
                        stream_requests[tcp_stream]["responses"].append(http_response_detail)
        self.analysis_results["http_all_data"] = stream_requests

    def save_structured_results(self):
        """将结构化结果保存到文件并计算统计信息"""
        # 计算总HTTP请求和响应数，遍历所有stream_id下的请求
        total_http_requests, total_http_responses = 0, 0
        request_methods,status_codes = {},{}

        for stream_id, stream_data in self.analysis_results["http_all_data"].items():
            # 统计请求数和响应数
            requests = stream_data["requests"]
            responses = stream_data["responses"]
            total_http_requests += len(requests)
            total_http_responses += len(responses)

            # 统计请求方法
            for req in requests:
                method = req.get("request_method", "Unknown")
                request_methods[method] = request_methods.get(method, 0) + 1

            # 统计响应状态码
            for resp in responses:
                # 从response_line中提取状态码
                status_line = resp.get("response_code", "Unknown")
                status_codes[status_line]=status_codes.get(status_line, 0) + 1

        # 转换set为list以便JSON序列化
        structured_data = {
            "analysis_summary": {
                "total_ips": len(self.analysis_results["ip_addresses"]),
                "total_domains": len(self.analysis_results["domains"]),
                "total_urls": len(self.analysis_results["urls"]),
                "total_http_streams": len(self.analysis_results["http_all_data"]),
                "total_http_requests": total_http_requests,
                "total_http_responses": total_http_responses,
                "request_methods": request_methods,
                "status_codes": status_codes
            },
            "ip_addresses": self.analysis_results["ip_addresses"],
            "domains": self.analysis_results["domains"],
            "urls": self.analysis_results["urls"],
            "http_all_data": self.analysis_results["http_all_data"],
            "basic_info": self.analysis_results["basic_info"],
            "protocols": self.analysis_results["protocols"]
        }
        self.jsonstr_to_file(structured_data)
        return structured_data

    def get_base_info(self,pcapfile_path):
        """调用系统命令capinfos直接获取流量包文件的基本信息。
        参数：
            self.filepath (str): 传入需要解析的流量包的路径
        返回：
            str: 讲流量包基本信息全部展示
        """
        response_result= self.run_tshark("流量包文件的基本信息", f"capinfos {pcapfile_path}")
        response_result += self.run_tshark("协议分级分布", f"tshark -r {pcapfile_path} -z io,phs -q")
        response_result += self.run_tshark("域名解析记录", f"tshark -r {pcapfile_path} -z hosts -q")
        response_result += self.run_tshark("流量包的凭据信息", f"tshark -r {pcapfile_path} -z credentials -q")
        return response_result


    def get_other_info(self,pcapfile_path):
        """调用tshark直接从流量包中收集其他信息，比如凭据信息、端口开放信息。
        参数：
            self.filepath (str): 传入需要解析的流量包的路径
        返回：
            str: 展示流量包凭据信息、端口开放信息
        """
        response_result=self.run_tshark("流量包的端口开放信息", f"tshark -r {pcapfile_path} -z dests,tree -q")
        response_result+=self.run_tshark("流量包的会话交互信息", f"tshark -r {pcapfile_path} -z conv,tcp -q")
        return response_result

    def get_http_protocol_info(self,pcapfile_path):
        """调用tshark直接从流量包中收集HTTP相关信息。
        参数：
            self.filepath (str): 传入需要解析的流量包的路径
        返回：
            str: 展示流量包HTTP相关信息
        """
        response_result = self.run_tshark("流量包中HTTP的状态码跟请求的分布情况",f"tshark -r {pcapfile_path} -z http,tree -q")
        response_result += self.run_tshark("流量包中HTTP的服务器名称和URI路径", f"tshark -r {pcapfile_path} -z http_req,tree -q")
        return response_result

    def get_dns_protocol_info(self,pcapfile_path):
        """调用tshark直接从流量包中收集DNS相关信息。
        参数：
            self.filepath (str): 传入需要解析的流量包的路径
        返回：
            str: 展示流量包DNS相关信息
        """
        response_result = self.run_tshark("流量包中DNS解析",f"tshark -r {pcapfile_path} -z dns,tree -q")
        return response_result
    def analysis_http_protocol(self,pcapfile_path):
        """调用tshark直接从流量包中分析HTTP信息。
        参数：
            self.filepath (str): 传入需要解析的流量包的路径
        返回：
            str: 将流量中的HTTP信息转换成结构化数据的一个路径
        """
        output=self.run_tshark("提取所有HTTP请求URL请求方法和状态码及数据",f"tshark -Y http -r {pcapfile_path} -T fields -e frame.number -e frame.time -e tcp.stream -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.request.method -e http.request.full_uri -e http.host -e http.file_data -e http.response.code -e http.response.line -e http.request.line -e http.request.version -e http.response.version")
        # 结构化处理
        self.parse_tshark_output(output)
        # 保存结果
        self.save_structured_results()

        # 遍历所有HTTP流，拿到想要解析的恶意请求
        fields_to_check = {}
        for stream_id, stream_data in self.analysis_results["http_all_data"].items():
            # 注意：这里应该是requests而不是responses，因为我们要检测请求中的攻击
            requests = stream_data.get("requests", [])
            # 遍历所有请求
            for request in requests:
                # 提取请求相关信息
                frame_id = request.get("number", "Unknown")
                full_uri = request.get("request_full_uri", "Unknown")
                request_data = request.get("request_data", "")
                request_line = request.get("request_line", {})

                # 创建要检测的字段字典
                fields_to_check[frame_id] = {
                    "full_uri": full_uri,
                    "request_data": request_data,
                    "request_line": request_line,
                }
        # 返回几个关键字段
        return fields_to_check

    def analyze_http_attacks(self,http_json_path,rules_json_path):
        """
        分析结构化数据，检测攻击行为，简要分析
        """
        # 读取检测规则文件
        with open(rules_json_path, 'r', encoding='utf-8') as f:
            http_attack_data = json.load(f)
        # 读取格式化之后的文件
        with open(http_json_path, 'r', encoding='utf-8') as f:
            attack_data = json.load(f)
        # 提取要识别的攻击行为
        http_info = attack_data["http_all_data"]
        requests_method, requests_full_uri, requests_request_data, requests_request_line, responses_data = "", "", "", "", ""
        # 初始化攻击检测结果
        attack_results = {
            "total_urls_scanned": len(attack_data["urls"]),
            "attacks_detected": 0,
            "attack_types_detected": [],
            "attack_type_counts": {},
            "attack_details": []
        }
        # 遍历每个攻击类型及其规则
        for attack_type in http_attack_data:
            attack_name = attack_type["attack_type"]
            data_rules = attack_type["data_rules"]
            detection_method = attack_type["detection_method"]
            description = attack_type["description"]
            # 遍历每个URL，检查是否匹配当前攻击类型的规则
            for id, content in http_info.items():
                # 检查URL路径是否匹配任何数据规则
                # 请求信息
                if content["requests"]:
                    requests_method = content["requests"][0]["request_method"]
                    requests_full_uri = content["requests"][0]["request_full_uri"]
                    requests_request_data = content["requests"][0]["request_data"]
                    requests_request_line = content["requests"][0]["request_line"]
                # 响应信息
                if content["responses"]:
                    responses_data = content["responses"][0]["response_data"]
                check_http_info = requests_method + requests_full_uri + requests_request_data + json.dumps(
                    requests_request_line) + responses_data

                for rule in data_rules:
                    if rule in check_http_info:
                        # 记录检测到的攻击
                        attack_results["attacks_detected"] += 1
                        # 如果是新的攻击类型，添加到列表中
                        if attack_name not in attack_results["attack_types_detected"]:
                            attack_results["attack_types_detected"].append(attack_name)
                        # 更新攻击类型计数
                        if attack_name not in attack_results["attack_type_counts"]:
                            attack_results["attack_type_counts"][attack_name] = 0
                        attack_results["attack_type_counts"][attack_name] += 1
                        # 添加攻击详情
                        attack_results["attack_details"].append({
                            "frame_id": id,
                            "url": requests_full_uri,
                            "request_data": requests_request_data,
                            "attack_type": attack_name,
                            "description": description,
                            "detection_method": detection_method,
                            "matched_rule": rule,
                            "responses_data": responses_data
                        })
                        break  # 每个URL只记录一次攻击类型
        # # 输出分析结果
        # with open('attack_analysis_results.json', 'w', encoding='utf-8') as f:
        #     json.dump(attack_results, f, indent=2, ensure_ascii=False)
        # 打印简要结果
        print(f"总扫描URL数: {attack_results['total_urls_scanned']}")
        print(f"检测到的攻击数: {attack_results['attacks_detected']}")
        print(f"检测到的攻击类型: {len(attack_results['attack_types_detected'])}")
        print(f"\n攻击类型及次数统计:")
        for attack_type, count in attack_results['attack_type_counts'].items():
            print(f"  {attack_type}: {count}次")
        print(f"\n攻击类型列表: {attack_results['attack_types_detected']}")
        print("\n攻击详情已保存到attack_analysis_results.json文件中")

    def get_max_info(self,http_json_path, key):
        # 读取attack.json文件
        with open(http_json_path, 'r', encoding='utf-8') as f:
            attack_data = json.load(f)

        # 提取要识别的攻击行为
        http_info = attack_data["http_all_data"]

        max_value = None
        attack_results = {}

        # 递归搜索函数，用于在嵌套结构中查找key
        def search_key(obj, current_path=""):
            nonlocal max_value, attack_results, current_id, current_content

            if isinstance(obj, dict):
                # 遍历字典的键值对
                for k, v in obj.items():
                    # 检查当前键是否匹配目标key
                    if k == key:
                        try:
                            # 尝试将值转换为整数
                            num_value = int(v)
                            # 更新最大值
                            if max_value is None or num_value > max_value:
                                max_value = num_value
                                # 保存相关信息
                                attack_results["attack_details"] = {
                                    "frame_id": current_id,
                                    "url": current_content["requests"][0]["request_full_uri"] if current_content["requests"] else "",
                                    "request_data": current_content["requests"][0]["request_data"] if current_content["requests"] else "",
                                    "request_line": current_content["requests"][0]["request_line"] if current_content["requests"] else "",
                                    "responses_data": current_content["responses"][0]["response_data"] if current_content["responses"] else "",
                                    "matched_key": k,
                                    "matched_value": v,
                                    "match_path": current_path + f".{k}" if current_path else k
                                }
                        except (ValueError, TypeError):
                            # 如果值不是数字，只记录但不比较
                            pass

                    # 检查当前值是否匹配目标key（作为字符串值）
                    if isinstance(v, str) and key in v:
                        # 对于字符串值包含key的情况，保存信息但不比较大小
                        pass

                    # 递归搜索子对象
                    search_key(v, current_path + f".{k}" if current_path else k)

            elif isinstance(obj, list):
                # 遍历列表的每个元素
                for i, item in enumerate(obj):
                    search_key(item, current_path + f"[{i}]" if current_path else f"[{i}]")

        # 遍历每个流，搜索key
        for current_id, current_content in http_info.items():
            search_key(current_content)

        # 打印结果
        print(attack_results)
        return attack_results



