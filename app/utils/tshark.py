import subprocess
import json
import csv
import os


tshark_cmd = None
# tshark cmd list
# -i <interface> : 캡처할 네트워크 인터페이스 지정.
# -D : 사용 가능한 네트워크 인터페이스 목록 표시.
# -f <BPF 필터> : 패킷 캡처 시 BPF 필터 적용(TCP/IP 레벨에서 작동).
# -r <file> : 파일로부터 캡처한 데이터를 읽음.
# -w <file> : 패킷 캡처 데이터를 파일로 저장.
# -Y <filter> : 디스플레이 필터 적용(현재 버전).
# -R <filter(old)> : 디스플레이 필터 적용(구버전).
# -T <output format> : 출력 형식 지정(text, fields, json, pdml 중 선택).
# -e <fields> : 특정 필드 값만 출력.
# -V : 패킷 세부정보를 상세히 출력.
# -z <statistics> : 통계 정보 출력(io,stat 또는 http,stat 등).
# -c <packet count> : 캡처할 패킷 수를 제한.   
    
pcap_file = "C:\\apache.pcap"

def user_input(): 
    return

def pcap_frame():
    frame_data = []
    frame_list = [
        "frame.number",                    # frame.time : 패킷의 캡처 시간                                                                             
        "frame.time",                      # frame.time_relative : 첫 번째 패킷과의 상대 시간 --> 패킷이 1개일 경우, 확인x                      
        "frame.time_relative",                                                                                                  
        "frame.time_epoch",                                                                                                 
        "frame.time_delta",                                                                                                 
        "frame.len",                                                    
        "frame.cap_len",                                                                                                    
        "frame.protocols",                                                                                                  
        "frame.marked"                                                  
        "frame.ignored",                                                                                                    
        "frame.interface_id",                                                                                                   
        "frame.offset_shift",                                                                                                   
        "frame.encap_type",                                                                                                 
        "frame.time_delta_displayed",                                                                                                   
        "frame.comment"                                                                                                 
        # "-e", "frame.pkt_len", --> x                                              
        # "-e", "frame.time_shift",  --> x      
                # frame.number : Packet 번호
        
        
        # frame.time_epoch : 패킷의 캡처 시간을 Epoch 시간(초)로 출력
        # frame.time_delta : 이전 프레임과의 시간 차이
        # frame.len : 프레임의 전체 길이 (byte 단위)
        # frame.cap_len : 캡처된 프레임 길이 (byte 단위)
        # frame.protocols : 프레임에 포함된 모든 프로토콜 계층
        # frame.marked : 프레임이 Wireshark에서 "Marked"로 표시되었는지 여부
        # frame.ignored : 프레임이 Wireshark에서 "Ignored"로 표시되었는지 여부
        # frame.interface_id : 캡처 인터페이스 ID
        # frame.offset_shift : 프레임 오프셋이 변경된 경우의 Shift 값
        # frame.pkt_len : 프레임의 실제 길이 (Wire Length) --> 사용 불가
        # frame.encap_type : 프레임의  캡슐화(encapsulation) 유형 (Ethernet, PPP 등).
        # frame.time_delta_displayed : 이전 표시된 프레임과의 시간 차이
        # frame.time_shift : 패킷에 적용된 시간 이동 값. --> 사용 불가
        # frame.comment : 프레임에 주석이 있는 경우 그 내용                                        
    ]

    for field in frame_list:
    # read pcap file
        tshark_cmd = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", field
        ]

        pcap_data = tshark_process(tshark_cmd)
        if pcap_data :
            print(f"{field} : {pcap_data}")
            frame_data.append(pcap_data)
        else:
            print(f"{field} : None")
            frame_data.append("None")

    return frame_data

def pcap_eth():
    eth_data = []
    eth_list = [
        "eth.src",         # eth.src : 출발지 MAC 주소                                
        "eth.dst",         # eth.dst : 목적지 MAC 주소                                
        "eth.type",        # eth.type : Ethernet Type 필드 (IPv4, Ipv6, ARP)                                
        "eth.addr",        # eth.addr : MAC 주소                                
        "eth.len",         # eth.len : Ethernet 프레임 길이                                
        "eth.trailer"      # eth.trailer : Ethernet 트레일러 (데이터의 무결성을 확인하거나 추가 정보를 전달)                                    
    ]

    for field in eth_list:
        tshark_cmd = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", field
        ]

        pcap_data = tshark_process(tshark_cmd)
        if pcap_data :
            print(f"{field} : {pcap_data}")
            eth_data.append(pcap_data)
        else:
            print(f"{field} : None")
            eth_data.append("None")

    return eth_data

def pcap_ipv():
    ip_data = []
    
    # Check Internet Protocol Version
    tshark_cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "fields",
        "-e", "ip.version"
    ]
    ipv = tshark_process(tshark_cmd)

    if ipv == "4":
        ipv4_list = [
            "ip.src",                # ip.src : 출발지 IP        
            "ip.dst",                # ip.dst : 목적지 IP        
            "ip.ttl",                # ip.ttl : Time To Live(TTL)        
            "ip.proto",              # ip.proto : 상위 프로토콜 (TCP, UDP, ICMP)        
            "ip.len",                # ip.len : IP 패킷의 전체 길이        
            "ip.id",                 # ip.id : 식별자        
            "ip.flags",              # ip.flags : 플래그        
            "ip.checksum",           # ip.checksum : 체크섬 (무결성)            
            "ip.dsfield"             # ip.dsfield : Differentiated Services Field (Qos 관련)            
        ]
        
        for field in ipv4_list:
            tshark_cmd = [
                "tshark",
                "-r", pcap_file,
                "-T", "fields",
                "-e", field
            ]

            pcap_data = tshark_process(tshark_cmd)
            if pcap_data:
                print(f"{field} : {pcap_data}")
                ip_data.append(pcap_data)
            else:
                print(f"{field} : None")
                ip_data.append("None")
            
    else:
        ipv6_list = [
            "ipv6.src",                  # ip.src : 출발지 IP         
            "ipv6.dst",                  # ip.dst : 목적지 IP         
            # "ipv6.ttl",                # ip.ttl : Time To Live(TTL)         
            # "ipv6.proto",              # ip.proto : 상위 프로토콜 (TCP, UDP, ICMP)             
            # "ipv6.len",                # ip.len : IP 패킷의 전체 길이         
            # "ipv6.id",                 # ip.id : 식별자         
            # "ipv6.flags",              # ip.flags : 플래그             
            # "ipv6.checksum",           # ip.checksum : 체크섬 (무결성)                 
            # "ipv6.dsfield",            # ip.dsfield : Differentiated Services Field (Qos 관련)             
            # "ipv6.traffic_class",      #                
            # "ipv6.flow_label",         #             
            # "ipv6.payload_length",     #                 
            # "ipv6.next_header"         #     

        ]

        for field in ipv6_list:
            tshark_cmd = [
                "tshark",
                "-r", pcap_file,
                "-T", "fields",
                "-e", field
            ]
            pcap_data = tshark_process(tshark_cmd)
            if pcap_data:
                print(f"{field} : {pcap_data}")
                ip_data.append(pcap_data)
            else:
                print(f"{field} : None")
                ip_data.append("None")
    return ip_data

def pcap_tl(ip_proto): # Transport Layer 
    tl_data = []
    protocol_list = {
        "1": "ICMP",    # ICMP (Internet Control Message Protocol)	네트워크 오류 보고 및 진단.        
        "6": "TCP",     # TCP (Transmission Control Protocol)	연결 지향적 전송 계층 프로토콜.    
        "17": "UDP",    # UDP (User Datagram Protocol)	연결 비지향적 전송 계층 프로토콜.        
        "41": "IPv6",   # IPv6 encapsulation	IPv6 패킷의 캡슐화를 나타냅니다.        
        "47": "GRE",    # GRE (Generic Routing Encapsulation)	터널링 프로토콜로, 여러 프로토콜을 캡슐화.        
        "50": "ESP",    # ESP (Encapsulating Security Payload)	IPsec에서 사용되는 데이터 암호화 프로토콜.        
        "51": "AH",     # AH (Authentication Header)	IPsec에서 사용되는 인증 헤더.   
        "89": "OSPF",   # OSPF (Open Shortest Path First)	라우팅 프로토콜.        
        "132": "SCTP"   # SCTP (Stream Control Transmission Protocol)	메시지 기반의 신뢰성 있는 전송 프로토콜.        
    }

    ip_proto = protocol_list[ip_proto]

    if ip_proto == "ICMP":
        icmp_list = [
            "icmp.type"	    # ICMP 메시지 타입 (예: Echo Request = 8)
            "icmp.code"	    # ICMP 메시지 코드
            "icmp.checksum"	# ICMP 체크섬
            "icmp.seq"	    # ICMP 시퀀스 번호
            "icmp.id"	    # ICMP 식별자
            "icmp.resp_in"	# 응답을 트리거한 요청 패킷
            "icmp.resp_out" # 요청에 대한 응답 패킷
        ]

        for field in icmp_list:
            tshark_cmd = [
                "tshark",
                "-r", pcap_file,
                "-T", "fields",
                "-e", field
            ]
            pcap_data = tshark_process(tshark_cmd)
            if pcap_data:
                print(f"{field} : {pcap_data}")
                tl_data.append(pcap_data)
            else:
                print(f"{field} : None")
                tl_data.append("None")
        return pcap_data
        
    elif ip_proto == "TCP":
        tcp_list = [
            "tcp.srcport",                  # 출발지 포트                   
            "tcp.dstport",                  # 목적지 포트                  
            "tcp.seq",                      # 시퀀스 번호
            "tcp.ack",                      # ACK 번호
            "tcp.flags",                    # 플래그
            "tcp.flags.syn",                # SYN 플래그
            "tcp.flags.ack",                # ACK 플래그
            "tcp.flags.fin",                # FIN 플래그
            "tcp.flags.reset",              # RST 플래그
            "tcp.flags.push",               # PSH 플래그
            "tcp.flags.urg",                # URG 플래그
            "tcp.len",                      # 페이로드 길이
            "tcp.window_size_value",        # 윈도우 크기 (수신 크기)
            "tcp.options",                  # 옵션
            "tcp.analysis.retransmission",  # 재전송 여부
            "tcp.analysis.lost_segment"     # 세그머트 손실 여부
        ]

        for field in tcp_list:
            tshark_cmd = [
                "tshark",
                "-r", pcap_file,
                "-T", "fields",
                "-e", field
            ]
            pcap_data = tshark_process(tshark_cmd)
            if pcap_data:
                print(f"{field} : {pcap_data}")
                tl_data.append(pcap_data)
            else:
                print(f"{field} : None")
                tl_data.append("None")
        return pcap_data
    
    elif ip_proto == "UDP":
        udp_list = [
            "udp.srcport",        # 출발지 포트
            "udp.dstport",        # 목적지 포트
            "udp.length",         # 패킷의 길이
            "udp.checksum",       # UDP 체크섬
            "udp.checksum.status" # 체크섬 상태 (유효 여부)
        ]
        a=3
    elif ip_proto == "GRE":
        gre_list = [
            "gre.flags",            # GRE flag
            "gre.version",          # GRE 프로토콜 버전
            "gre.protocol"          # GRE 캡슐화된 상위 계층 프로토콜의 번호
        ]
        a=5
    # elif ip_proto == "ESP":
    #     esp_list = [
    #         "esp.spi",              #           
    #         "esp.sequence",         #               
    #         "esp.payload",          #               
    #         "esp.auth_data"         #               
    #     ]
    #     a=6
    # elif ip_proto == "AH":
    #     a=7
    # elif ip_proto == "OSPF":
    #     a=8
    # elif ip_proto == "SCTP": 
    #     a=9
    else:
        print("ErroR")
        
    tshark_cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "fields"
    ]
    
    return

def tshark_process(tshark_cmd):
    pcap_data = subprocess.run(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode byte string
    decoded_string = pcap_data.stdout.decode('utf-8')
    cleaned_string = decoded_string.strip()
    return cleaned_string

def process_packet():
    return

def process_tshark():
    return

def main():
    # data = process_tshark()
    frame_data = pcap_frame()
    print("--------------------------------------------------------")
    eth_data = pcap_eth()
    print("--------------------------------------------------------")
    ipv_data = pcap_ipv()
    print("--------------------------------------------------------")
    ip_proto = 6
    
    return

if __name__ == "__main__":
    main()