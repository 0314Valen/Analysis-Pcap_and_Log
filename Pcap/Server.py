import json
import os

from pathlib import Path
from mcp.server.fastmcp import FastMCP, Context
from Pcap_analysis import CapInfo
from fastmcp.resources import FileResource, TextResource, DirectoryResource

# 创建对象
cap = CapInfo()
# Initialize FastMCP server
mcp = FastMCP(name="Pcap_analysis", log_level="ERROR",instructions="""This tool is used for traffic package analysis, including protocols such as HTTP, DNS, and can analyse whether malicious behaviour is preserved""")

# # 4. 暴露目录列表
# data_dir_path = Path("./app_data").resolve()
# if data_dir_path.is_dir():
#     data_listing_resource = DirectoryResource(
#         uri="resource://",
#         path=data_dir_path, # 目录的路径
#         name="Data Directory Listing",
#         description="列出数据目录中可用的文件。",
#         recursive=False # 设置为 True 以列出子目录
#     )
#     mcp.add_resource(data_listing_resource) # 返回文件的 JSON 列表

# tools1:获取基本信息
@mcp.tool(description="Use the system command capinfos to directly obtain basic information about the traffic packet file,Basic information of the traffic package files, protocol level distribution, domain name resolution records, credential information, port opening information")
async def get_pcap_info(pcapfile_path: str) -> str:
    """Use the system command capinfos to directly obtain basic information about the traffic packet file,Basic information of the traffic package files, protocol level distribution, domain name resolution records, credential information, port opening information
    Args:
        pcapfile_path: Path of the pcap file to be analysed
    """
    cap.check_file(pcapfile_path)
    response_base_info=cap.get_base_info(pcapfile_path) # 包含流量包文件的基本信息、协议分级分布、域名解析记录、凭据信息、端口开放信息
    return response_base_info.strip()

# tools2:获取其他信息
@mcp.tool(description="Use tshark to analyse traffic packets for information on open ports, session interactions, and basic DNS information.")
async def get_other_info(pcapfile_path: str) -> str:
    """Use tshark to analyse traffic packets for information on open ports, session interactions, and basic DNS information.
    Args:
        pcapfile_path: Path of the pcap file to be analysed
    """
    cap.check_file(pcapfile_path)
    response_other_info=cap.get_other_info(pcapfile_path) #包含端口开放信息，会话交互信息
    response_dns_info = cap.get_dns_protocol_info(pcapfile_path) #获取dns的基本信息
    return response_other_info.strip()+response_dns_info.strip()

# tools3:获取HTTP基本信息
@mcp.tool(description="The distribution of HTTP status codes and requests in the traffic package file, and the server names and URI paths of HTTP in the traffic package")
async def get_httpr_info(pcapfile_path: str) -> str:
    """The distribution of HTTP status codes and requests in the traffic package file, and the server names and URI paths of HTTP in the traffic package
    Args:
        pcapfile_path: Path of the pcap file to be analysed
    """
    cap.check_file(pcapfile_path)
    response_http_protocol_info=cap.get_http_protocol_info(pcapfile_path) #包含流量包中HTTP的状态码跟请求的分布情况、流量包中HTTP的服务器名称和URI路径
    return response_http_protocol_info.strip()

# tools4:获取HTTP所有请求信息
@mcp.tool(description="Extract all HTTP protocol requests and analyse potential attack information")
async def analysis_http_info(pcapfile_path: str) -> str:
    """Extract all HTTP protocol requests and analyse potential attack information
    Args:
        pcapfile_path: Path of the pcap file to be analysed
    """
    cap.check_file(pcapfile_path)
    http_info=cap.analysis_http_protocol(pcapfile_path)
    outfile=pcapfile_path.replace(".pcap", "_http_info.json")
    with open(outfile, 'w', encoding='utf-8') as f:
        json.dump(http_info, f, ensure_ascii=False, indent=2)
    return outfile


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')