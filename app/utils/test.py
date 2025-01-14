import subprocess
import json

pcap_file = "C:\\test.pcapng"
# pcap_file = "C:\\apache.pcap"

def tshark_json(pcap_json):
    extracted_data = []
    for index, packet in enumerate(pcap_json):
        # json data frame
        # {
        #     "_index": "packets-2025-01-06",
        #     "_type": "doc",
        #     "_score": null,
        #     "_source": {
        #         "layers": {
        #             "frame": {
        layers = packet.get("_source", {}).get("layers", {})
        ip_src = layers.get("ip", {}).get("ip.src", "N/A")
        ip_dst = layers.get("ip", {}).get("ip.dst", "N/A")
        ip_proto = layers.get("ip", {}).get("ip.proto", "N/A")

        print(f"index: {index}, src: {ip_src}, dst: {ip_dst}, protocol: {ip_proto}")

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
    return

def tshark_subporcess(thsark_cmd):
    pcap_json = subprocess.run(thsark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pcap_json = json.loads(pcap_json.stdout)
    return pcap_json
    
def main():
    thsark_cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "json"
    ]
    pcap_data = tshark_subporcess(thsark_cmd)
    pcap_json = tshark_json(pcap_data)

if __name__ == "__main__":
    main()