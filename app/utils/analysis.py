import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime
import time
import subprocess
import json

# pcap_file = "C:\\test.pcapng"
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
        "2": "igmp",    # IGMP 인터넷 그룹 관리 프로토콜
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
        # IP
        layers = packet.get("_source", {}).get("layers", {})
        ip_src = layers.get("ip", {}).get("ip.src", "N/A")
        ip_dst = layers.get("ip", {}).get("ip.dst", "N/A")
        ip_proto = layers.get("ip", {}).get("ip.proto", "N/A")
        ip_proto = protocol_list[ip_proto]
        ip_src_port = layers.get(f"{ip_proto}", {}).get(f"{ip_proto}.srcport", "N/A")
        ip_dst_port = layers.get(f"{ip_proto}", {}).get(f"{ip_proto}.dstport", "N/A")

        # FRAME
        time_epoch = layers.get("frame", {}).get("frame.time_epoch", "N/A")
        frame_len = layers.get("frame", {}).get("frame.len", "N/A")

        packet_info = {
            "ip_proto": ip_proto,
            "ip_src": ip_src,
            "ip_srcport": ip_src_port,
            "ip_dst": ip_dst,
            "ip_dstport": ip_dst_port,

            "time_epoch": time_epoch,
            "frame_len": frame_len
        }
        
        extracted_data.append(packet_info)
        
    return extracted_data


def tshark_counts(pcap_json):
    # total packet 
    total_counts = len(pcap_json)
    
    # ip counts
    src_counts = Counter([packet["ip_src"] for packet in pcap_json])
    dst_counts = Counter([packet["ip_dst"] for packet in pcap_json])
    protocol_counts = Counter([packet["ip_proto"] for packet in pcap_json])
    # Counter({'tcp': 120, 'udp': 75, 'icmp': 10, 'unknown': 5})

    # averages packet size
    packet_sizes = [int(packet["frame_len"]) for packet in pcap_json]
    average_packet_size = sum(packet_sizes) / len(packet_sizes)

    # packet times, average_pps
    timestamps = [int(float(packet["time_epoch"])) for packet in pcap_json]
    packet_counts = Counter(timestamps)
    # Counter({1737039567: 782, 1737039568: 433, ...})

    total_packets = sum(packet_counts.values())
    total_seconds = len(packet_counts)
    average_pps = round(total_packets / total_seconds, 2)
    average_bps = round(average_pps * average_packet_size * 8, 2) # averag_bps (BPS = PPS * average_packet * 8)

    # 평균 pps 보다 큰 패킷들
    abnormal_times = [time for time, count in packet_counts.items() if count > average_pps]
    abnormal_packets = [packet for packet in pcap_json if int(float(packet["time_epoch"])) in abnormal_times]
    abnormal_ip = Counter([packet["ip_src"] for packet in abnormal_packets])

    x_times = list(packet_counts.keys())
    y_packet = list(packet_counts.values())
    plt.bar(x_times, y_packet, color=['red' if time in abnormal_times else 'blue' for time in x_times], label="Packet Count")
    # Plot average PPS line
    plt.axhline(y=average_pps, color='green', linestyle='--', label=f"Average PPS ({average_pps})")

    # Labels and legend
    plt.xlabel("Time (seconds)")
    plt.ylabel("Packet Count")
    plt.title("Packet Counts Over Time with Abnormal Times Highlighted")
    plt.legend()

    # Show plot
    plt.tight_layout()
    plt.show()


    return protocol_counts


def tshark_chart(protocol_counts):
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.figure(figsize=(10, 6))
    plt.bar(protocols, counts)
    plt.xlabel('Protocol')
    plt.ylabel('packet Count')
    plt.title('Protocol Distribution')
    plt.show()
    
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
    pcap_chart = tshark_chart(pcap_counts)

if __name__ == "__main__":
    main()