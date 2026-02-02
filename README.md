# Analysis-Pcap_and_Log

## 网络日志与流量分析工具

一个用于分析网络日志和流量包的综合性工具集，支持Apache日志、Windows EVTX日志和PCAP流量包的分析，提供IP提取、攻击检测、数据可视化等功能。

### 功能特性

#### 日志分析 (Log 文件夹)

1. **Apache日志分析** (`Log_Apache.py`)
   - 支持分析Apache访问日志
   - 支持IPv4、IPv6地址、主机名和域名
   - 支持包含或不包含用户名的日志格式
   - 支持包含或不包含请求体的日志格式
   - 生成IP信息和状态码分布等统计报告
   - 支持多线程处理

2. **Windows日志分析** (`Log_Windows.py`)
   - 分析Windows EVTX日志文件
   - 提取日志中的IP地址和事件ID
   - 生成详细的分析结果
   - 支持多线程处理

3. **IP提取工具**
   - `Get_file_IP.py`: 从多个文件中提取IP地址并关联文件路径
   - `Get_IP.py`: 读取文件中的IP地址并检查重复IP

#### 流量包分析 (Pcap 文件夹)

1. **PCAP文件分析** (`Pcap_analysis.py`)
   - 分析PCAP文件并生成结构化JSON数据
   - 检测HTTP攻击行为
   - 递归搜索JSON结构中的最大值
   - 支持多线程处理

2. **攻击可视化** (`visualize_attack_data.py`)
   - 生成请求方法分布饼图
   - 生成HTTP状态码分布柱状图
   - 生成URL路径深度分布柱状图
   - 生成URL路径前缀分布柱状图
   - 生成IP地址分布柱状图
   - 生成域名分布柱状图
   - 生成HTML报告

3. **MCP服务器脚本** (`Server.py`)
   - 调用支持MCP，但是取的数据有点多，对token是一种浪费

4. **示例调用脚本** (`main.py`)
   - 提供完整的调用用例
   - 包含5个详细的示例，覆盖PCAP分析和攻击检测
   - 提供测试JSON演示功能

### 目录结构

```
/
├── Log/                    # 日志分析工具
│   ├── Get_file_IP.py      # 从文件中提取IP并关联文件路径
│   ├── Get_IP.py           # 读取文件中的IP并检查重复
│   ├── Log_Apache.py       # Apache日志分析工具
│   └── Log_Windows.py      # Windows EVTX日志分析工具
├── Pcap/                   # 流量包分析工具
│   ├── main.py             # 示例调用脚本
│   ├── Pcap_analysis.py    # PCAP文件分析核心脚本
│   ├── Server.py           # MCP服务器辅助脚本
│   ├── visualize_attack_data.py  # 攻击数据可视化脚本
│   └── rules/              # 攻击检测规则
├── Analysis_Apache/        # [生成]Apache日志分析结果
├── Analysis_Windows/       # [生成]Windows日志分析结果
├── Windows/                # Windows日志样本
├── access-2024-06-25.log   # Apache日志样本
├── requirements.txt		# 项目依赖
└── README.md               # 项目说明文档
```

### 安装说明

1. 克隆项目到本地

   ```bash
   git clone <项目地址>
   cd rules
   ```

2. 安装依赖

   ```bash
   pip install -r requirements.txt
   ```

3. 依赖列表

   - python-evtx: 用于处理Windows EVTX日志
   - tqdm: 用于显示进度条
   - matplotlib: 用于数据可视化
   - seaborn: 用于数据可视化
   - numpy: 用于数据分析
   - pandas: 用于数据分析

### 使用方法

#### 1. Apache日志分析

```bash
python Log/Log_Apache.py
```

#### 2. Windows日志分析

```bash
python Log/Log_Windows.py
```

#### 3. 从文件中提取IP

```bash
python Log/Get_file_IP.py
```

#### 4. PCAP文件分析

```bash
python Pcap/main.py
```

#### 5. 攻击数据可视化

```bash
python Pcap/visualize_attack_data.py
```

### 示例用例

#### 示例1: 分析PCAP文件

```python
from Pcap_analysis import CapInfo

cap = CapInfo()
pcapfile_path = "./file/attack.pcap"
cap.check_file(pcapfile_path)
response_info = cap.analysis_http_protocol(pcapfile_path)
```

#### 示例2: 分析JSON文件中的攻击行为

```python
json_path = "./file/attack.json"
attack_rules_path = "./rules/merged_attack_data.json"
attack_results = cap.analyze_http_attacks(http_json_path=json_path, rules_json_path=attack_rules_path)
```

#### 示例3: 递归搜索JSON中的最大值

```python
json_path = "./file/attack.json"
content_length_result = cap.get_max_info(json_path, "Content-Length")
```

### 配置说明

#### Log_Apache.py配置

- `directory`: 日志文件目录
- `save_directory`: 分析结果保存目录

#### Log_Windows.py配置

- `directory`: EVTX日志文件目录
- `save_directory_path`: 分析结果保存目录

#### Pcap_analysis.py配置

- `outfile`: 分析结果保存文件
- `debug`: 调试模式开关

### 输出文件说明

#### Apache日志分析输出

- `ip_urls.json`: 单个日志文件的IP访问URL信息
- `all.json`: 合并所有日志文件的分析结果
- `all_404.json`: 404错误统计
- `all_ip.txt`: 所有IP地址列表
- `request_count.json`: 请求次数统计
- `status_count.json`: 状态码分布统计
- `file_downloads.json`: 文件下载统计
- `analysis_report.txt`: 详细分析报告

#### Windows日志分析输出

- `filename_ip_info.json`: 单个日志文件的IP信息
- `filename_id_info.json`: 单个日志文件的事件ID信息
- `all.json`: 合并所有日志文件的分析结果
- `all_ip.txt`: 所有IP地址列表

### 下一步计划

支持更多协议、日志

日志可视化

### 贡献指南

1. 提交 Pull Request

### 许可证

本项目采用 MIT 许可证

### 联系方式

如有问题或建议，请通过以下方式联系：

- Email: pr1n7@foxmail.com

### 致谢

- 感谢所有为本项目做出贡献的开发者
- 感谢python-evtx库提供的EVTX文件处理功能
- 感谢tshark工具提供的PCAP文件分析支持
- 感谢matplotlib和seaborn库提供的数据可视化功能
