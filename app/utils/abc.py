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

proto = "6"

print(protocol_list[proto])