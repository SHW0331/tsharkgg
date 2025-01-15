import matplotlib.pyplot as plt
from collections import Counter
import subprocess
import json

pcap_file = "C:\\test.pcapng"
# pcap_file = "C:\\apache.pcap"

def tshark_subporcess(thsark_cmd):
    pcap_json = subprocess.run(thsark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pcap_json = json.loads(pcap_json.stdout)
    return pcap_json

def tshark_json(pcap_data):
    extracted_data = []
    protocol_list = {
        "1": "icmp",    # ICMP (Internet Control Message Protocol)	네트워크 오류 보고 및 진단.        
        "6": "tcp",     # TCP (Transmission Control Protocol)	연결 지향적 전송 계층 프로토콜.    
        "17": "udp",    # UDP (User Datagram Protocol)	연결 비지향적 전송 계층 프로토콜.        
        "41": "ipv6",   # IPv6 encapsulation	IPv6 패킷의 캡슐화를 나타냅니다.        
        "47": "gre",    # GRE (Generic Routing Encapsulation)	터널링 프로토콜로, 여러 프로토콜을 캡슐화.        
        "50": "esp",    # ESP (Encapsulating Security Payload)	IPsec에서 사용되는 데이터 암호화 프로토콜.        
        "51": "ah",     # AH (Authentication Header)	IPsec에서 사용되는 인증 헤더.   
        "89": "ospf",   # OSPF (Open Shortest Path First)	라우팅 프로토콜.        
        "132": "sctp",  # SCTP (Stream Control Transmission Protocol)	메시지 기반의 신뢰성 있는 전송 프로토콜.        
        "N/A": "N/A"
    }    
    
    for index, packet in enumerate(pcap_data):
        layers = packet.get("_source", {}).get("layers", {})
        ip_src = layers.get("ip", {}).get("ip.src", "N/A")
        ip_dst = layers.get("ip", {}).get("ip.dst", "N/A")
        ip_proto = layers.get("ip", {}).get("ip.proto", "N/A")
        ip_proto = protocol_list[ip_proto]
        ip_src_port = layers.get(f"{ip_proto}", {}).get(f"{ip_proto}.srcport", "N/A")
        ip_dst_port = layers.get(f"{ip_proto}", {}).get(f"{ip_proto}.dstport", "N/A")

        packet_info = {
            "ip_proto": ip_proto,
            "ip_src": ip_src,
            "ip_srcport": ip_src_port,
            "ip_dst": ip_dst,
            "ip_dstport": ip_dst_port
        }
        
        extracted_data.append(packet_info)
        
    return extracted_data

def tshark_counts(pcap_json):
    protocol_counts = Counter([packet["ip_proto"] for packet in pcap_json])
    # print(protocol_counts)
    # Counter({'tcp': 120, 'udp': 75, 'icmp': 10, 'unknown': 5})
    
    return protocol_counts

def tshark_chart(pcap_json):
    protocols = 
    
    return
    
def main():
    thsark_cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "json"
    ]
    pcap_data = tshark_subporcess(thsark_cmd)
    pcap_json = tshark_json(pcap_data)
    pcap_counts = tshark_counts(pcap_json)
    pcap_graph = None

if __name__ == "__main__":
    main()