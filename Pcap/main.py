import json
import os
from Pcap_analysis import CapInfo

def check_file_exists(file_path):
    """检查文件是否存在"""
    return os.path.exists(file_path)


# 创建对象
cap = CapInfo(debug=True)  # 启用调试模式

# ==================== 示例1: 分析PCAP文件并生成JSON ====================
print("示例1: 分析PCAP文件并生成JSON")
print("=" * 50)

try:
    # 设置PCAP文件路径 (用户需要根据实际情况修改)
    pcapfile_path = "./file/attack.pcap"

    if check_file_exists(pcapfile_path):
        # 检查文件是否存在且格式正确
        cap.check_file(pcapfile_path)
        print(f"✓ 成功检查文件: {pcapfile_path}")
        # 分析HTTP协议并生成JSON文件
        response_info = cap.analysis_http_protocol(pcapfile_path)
        print(f"✓ 成功分析PCAP文件，结果已保存到: {cap.outfile}")
        print(f"  生成的JSON文件包含: {response_info}")
    else:
        print(f"⚠ 文件不存在: {pcapfile_path}")
        print(f"  请将PCAP文件放置在 {os.path.abspath(pcapfile_path)}")
except Exception as e:
    print(f"✗ 分析PCAP文件失败: {e}")
print()

# ==================== 示例2: 分析JSON文件中的攻击行为 ====================
print("示例2: 分析JSON文件中的攻击行为")
print("=" * 50)
try:
    # 设置JSON文件路径 (用户需要根据实际情况修改)
    json_path = "./file/attack.json"
    attack_rules_path = "./rules/data_rules.json"  # 使用data_rules.json作为默认规则
    if check_file_exists(json_path):
        if check_file_exists(attack_rules_path):
            # 分析HTTP攻击
            attack_results = cap.analyze_http_attacks(http_json_path=json_path, rules_json_path=attack_rules_path)
            print(f"✓ 成功分析攻击行为")
            print(f"  总扫描URL数: {attack_results['total_urls_scanned']}")
            print(f"  检测到的攻击数: {attack_results['attacks_detected']}")
            print(f"  检测到的攻击类型: {len(attack_results['attack_types_detected'])}")
            print(f"  攻击结果已保存到: attack_analysis_results.json")
            if attack_results['attack_type_counts']:
                print(f"  攻击类型统计:")
                for attack_type, count in attack_results['attack_type_counts'].items():
                    print(f"    - {attack_type}: {count}次")
        else:
            print(f"⚠ 攻击规则文件不存在: {attack_rules_path}")
            print(f"  请确保规则文件存在")
    else:
        print(f"⚠ JSON文件不存在: {json_path}")
        print(f"  请先运行示例1生成JSON文件，或确保文件存在")
except Exception as e:
    print(f"✗ 分析攻击行为失败: {e}")
print()

# ==================== 示例3: 递归搜索JSON中的最大值 ====================
print("示例3: 递归搜索JSON中的最大值")
print("=" * 50)
try:
    # 设置JSON文件路径 (用户需要根据实际情况修改)
    json_path = "./file/attack.json"
    if check_file_exists(json_path):
        # 示例3.1: 搜索Content-Length最大值
        print("  搜索 'Content-Length' 最大值:")
        content_length_result = cap.get_max_info(json_path, "Content-Length")
        if content_length_result and "attack_details" in content_length_result:
            print(f"    ✓ 找到最大值: {content_length_result['attack_details']['matched_value']}")
            print(f"    ✓ 帧ID: {content_length_result['attack_details']['frame_id']}")
        else:
            print(f"    ⚠ 未找到 'Content-Length' 字段或无数值数据")
    else:
        print(f"⚠ JSON文件不存在: {json_path}")
        print(f"  请先运行示例1生成JSON文件，或确保文件存在")
except Exception as e:
    print(f"✗ 递归搜索失败: {e}")

print()

# ==================== 示例4: 使用默认规则分析 ====================
print("示例4: 使用默认规则分析")
print("=" * 50)

try:
    # 只传入JSON文件路径，使用默认规则
    json_path = "./file/attack.json"

    if check_file_exists(json_path):
        default_results = cap.analyze_http_attacks(http_json_path=json_path)
        print(f"✓ 使用默认规则成功分析")
        print(f"  检测到攻击数: {default_results['attacks_detected']}")
    else:
        print(f"⚠ JSON文件不存在: {json_path}")
        print(f"  请先运行示例1生成JSON文件，或确保文件存在")
except Exception as e:
    print(f"✗ 使用默认规则分析失败: {e}")

print()

# ==================== 示例5: 快速演示 - 生成测试JSON ====================
print("示例5: 快速演示 - 创建测试JSON结构")
print("=" * 50)

try:
    # 创建一个简单的测试JSON文件用于演示

    # 保存测试JSON
    test_json_path = "./file/attack.json"
    key="Content-Length"
    # 使用测试JSON演示递归搜索
    print(f"\n  使用测试JSON演示 'Content-Length' 搜索:")
    test_result = cap.get_max_info(test_json_path, key)
    if test_result and "attack_details" in test_result:
        print(f"    ✓ 找到最大值: {test_result['attack_details']['matched_value']}")
        print(f"    ✓ 帧ID: {test_result['attack_details']['frame_id']}")
        print(f"    ✓ URL: {test_result['attack_details']['url']}")
        print(f"  ✓ 递归搜索功能演示成功!")
except Exception as e:
    print(f"✗ 测试演示失败: {e}")

print()
print("所有示例执行完成！")
print("\n使用说明:")
print("1. 请确保PCAP文件存在于 ./file/attack.pcap")
print("2. 请确保攻击规则文件存在于 ./rules/data_rules.json")
print("3. 可以修改示例中的文件路径以适应实际环境")
print("4. 示例5创建了一个测试JSON，可用于快速演示递归搜索功能")
