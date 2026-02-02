import json
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# 展示
# 生成HTML报告文件来查看完整的可视化分析结果，了解attack.json中的攻击数据分布情况。

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

# 读取attack.json文件
with open('../file/attack.json', 'r', encoding='utf-8') as f:
    attack_data = json.load(f)


# 1. 可视化请求方法分布
def plot_request_methods():
    methods = attack_data['analysis_summary']['request_methods']
    labels = list(methods.keys())
    sizes = list(methods.values())
    colors = ['#ff9999', '#66b3ff']

    plt.figure(figsize=(8, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    plt.title('请求方法分布')
    plt.axis('equal')
    plt.tight_layout()
    plt.savefig('request_methods.png', dpi=300, bbox_inches='tight')
    plt.close()


# 2. 可视化状态码分布
def plot_status_codes():
    status_codes = attack_data['analysis_summary']['status_codes']
    labels = list(status_codes.keys())
    values = list(status_codes.values())
    colors = sns.color_palette('viridis', len(labels))

    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, values, color=colors)
    plt.title('HTTP状态码分布')
    plt.xlabel('状态码')
    plt.ylabel('数量')

    # 在柱状图上添加数值
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2., height, f'{height}',
                 ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig('status_codes.png', dpi=300, bbox_inches='tight')
    plt.close()


# 3. 可视化URL路径深度分布
def plot_url_depth():
    urls = list(attack_data['urls'].keys())
    depth_counts = Counter()

    for url in urls:
        # 提取路径部分，忽略域名和查询参数
        try:
            if '://' in url:
                # 有协议的URL
                path = url.split('://')[1].split('/')[1:]  # 去掉协议和域名
            else:
                # 没有协议的URL，直接分割路径
                path = url.split('/')[1:]  # 直接分割路径
            depth = len([p for p in path if p])  # 计算路径深度
            depth_counts[depth] += 1
        except Exception as e:
            # 跳过无法处理的URL
            continue

    depths = sorted(depth_counts.keys())
    counts = [depth_counts[d] for d in depths]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(depths, counts, color='#88c999')
    plt.title('URL路径深度分布')
    plt.xlabel('路径深度')
    plt.ylabel('URL数量')

    # 在柱状图上添加数值
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2., height, f'{height}',
                 ha='center', va='bottom')

    plt.xticks(depths)
    plt.tight_layout()
    plt.savefig('url_depth.png', dpi=300, bbox_inches='tight')
    plt.close()


# 4. 可视化URL路径前缀分布（前10个）
def plot_url_prefixes():
    urls = list(attack_data['urls'].keys())
    prefix_counts = Counter()

    for url in urls:
        # 提取前两个路径段
        try:
            if '://' in url:
                # 有协议的URL
                path = url.split('://')[1].split('/')[1:]  # 去掉协议和域名
            else:
                # 没有协议的URL，直接分割路径
                path = url.split('/')[1:]  # 直接分割路径
            if path:
                prefix = '/' + path[0]  # 第一个路径段
                prefix_counts[prefix] += 1
        except Exception as e:
            # 跳过无法处理的URL
            continue

    # 取前10个最常见的前缀
    top_prefixes = prefix_counts.most_common(10)
    prefixes = [item[0] for item in top_prefixes]
    counts = [item[1] for item in top_prefixes]
    colors = sns.color_palette('plasma', len(prefixes))

    plt.figure(figsize=(12, 8))
    bars = plt.barh(prefixes, counts, color=colors)
    plt.title('URL路径前缀分布（前10个）')
    plt.xlabel('数量')
    plt.ylabel('路径前缀')

    # 在柱状图上添加数值
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 1, bar.get_y() + bar.get_height() / 2., f'{width}',
                 ha='left', va='center')

    plt.tight_layout()
    plt.savefig('url_prefixes.png', dpi=300, bbox_inches='tight')
    plt.close()


# 5. 可视化IP地址分布（前10个）
def plot_ip_addresses():
    ip_addresses = attack_data['ip_addresses']
    # 转换为列表并排序
    ip_list = sorted(ip_addresses.items(), key=lambda x: x[1]['sum'], reverse=True)[:10]
    ips = [item[0] for item in ip_list]
    counts = [item[1]['sum'] for item in ip_list]
    colors = sns.color_palette('magma', len(ips))

    plt.figure(figsize=(12, 8))
    bars = plt.barh(ips, counts, color=colors)
    plt.title('IP地址分布（前10个）')
    plt.xlabel('请求数量')
    plt.ylabel('IP地址')

    # 在柱状图上添加数值
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 1, bar.get_y() + bar.get_height() / 2., f'{width}',
                 ha='left', va='center')

    plt.tight_layout()
    plt.savefig('ip_addresses.png', dpi=300, bbox_inches='tight')
    plt.close()


# 6. 可视化域名分布
def plot_domains():
    domains = attack_data['domains']
    # 转换为列表并排序
    domain_list = sorted(domains.items(), key=lambda x: x[1]['sum'], reverse=True)
    domain_names = [item[0] if item[0] else '空域名' for item in domain_list]
    counts = [item[1]['sum'] for item in domain_list]
    colors = sns.color_palette('inferno', len(domain_names))

    plt.figure(figsize=(12, 8))
    bars = plt.barh(domain_names, counts, color=colors)
    plt.title('域名分布')
    plt.xlabel('请求数量')
    plt.ylabel('域名')

    # 在柱状图上添加数值
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 1, bar.get_y() + bar.get_height() / 2., f'{width}',
                 ha='left', va='center')

    plt.tight_layout()
    plt.savefig('domains.png', dpi=300, bbox_inches='tight')
    plt.close()


# 7. 生成HTML报告
def generate_html_report():
    # 填充摘要数据
    summary = attack_data['analysis_summary']

    # 使用字符串拼接，避免格式化冲突
    html_content = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack.json 可视化报告</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            text-align: center;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .section {{
            background-color: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #444;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }}
        .image-container {{
            text-align: center;
            margin: 20px 0;
        }}
        img {{
            max-width: 100%;
            height: auto;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary {{
            background-color: #e8f5e8;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .summary h3 {{
            margin-top: 0;
            color: #2e7d32;
        }}
    </style>
</head>
<body>
    <h1>Attack.json 可视化报告</h1>
    <div class="container">
        <div class="section">
            <div class="summary">
                <h3>分析摘要</h3>
                <p><strong>总URL数:</strong> {summary['total_urls']}</p>
                <p><strong>总HTTP流数:</strong> {summary['total_http_streams']}</p>
                <p><strong>总HTTP请求数:</strong> {summary['total_http_requests']}</p>
                <p><strong>总HTTP响应数:</strong> {summary['total_http_responses']}</p>
            </div>
        </div>

        <div class="section">
            <h2>1. 请求方法分布</h2>
            <div class="image-container">
                <img src="request_methods.png" alt="请求方法分布">
            </div>
        </div>

        <div class="section">
            <h2>2. HTTP状态码分布</h2>
            <div class="image-container">
                <img src="status_codes.png" alt="状态码分布">
            </div>
        </div>

        <div class="section">
            <h2>3. URL路径深度分布</h2>
            <div class="image-container">
                <img src="url_depth.png" alt="URL路径深度分布">
            </div>
        </div>

        <div class="section">
            <h2>4. URL路径前缀分布</h2>
            <div class="image-container">
                <img src="url_prefixes.png" alt="URL路径前缀分布">
            </div>
        </div>

        <div class="section">
            <h2>5. IP地址分布</h2>
            <div class="image-container">
                <img src="ip_addresses.png" alt="IP地址分布">
            </div>
        </div>

        <div class="section">
            <h2>6. 域名分布</h2>
            <div class="image-container">
                <img src="domains.png" alt="域名分布">
            </div>
        </div>
    </div>
</body>
</html>'''

    with open('attack_visualization_report.html', 'w', encoding='utf-8') as f:
        f.write(html_content)


# 运行所有可视化函数
if __name__ == '__main__':
    print("开始生成可视化图表...")
    plot_request_methods()
    print("✓ 请求方法分布图表生成完成")

    plot_status_codes()
    print("✓ 状态码分布图表生成完成")

    plot_url_depth()
    print("✓ URL路径深度图表生成完成")

    plot_url_prefixes()
    print("✓ URL路径前缀图表生成完成")

    plot_ip_addresses()
    print("✓ IP地址分布图表生成完成")

    plot_domains()
    print("✓ 域名分布图表生成完成")

    generate_html_report()
    print("✓ HTML报告生成完成")

    print("\n所有可视化图表和报告已生成完成！")
    print("报告文件: attack_visualization_report.html")
    print("图表文件: request_methods.png, status_codes.png, url_depth.png, url_prefixes.png, ip_addresses.png, domains.png")
