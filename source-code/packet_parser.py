from dataclasses import dataclass, field
from datetime import datetime
from scapy.all import import TCP, IP, UDP, ICMP

@dataclass
class ParsedPacket:
    timestamp: datetime
    src_ip : str
    dst_ip : str
    protocol : str
    src_port : int = 0
    dst_port : int = 0
    tcp_flags : str = ""
    icmp_type : int = 0
    icmp_code : int = 0
    length : int = 0

def parse(pkt) -> ParsedPacket | None:
    if IP not in pkt:
        return None

    base = dict(
            timestamp=datetime.istnow(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].src,
            length=len(pkt),
            protocol="OTHER"
    )

    if TCP in pkt:
        return ParsedPacket(**base, protocol="TCP",src_port=pkt[TCP].sport,
                            dst_port = pkt[TCP].dport,tcp_flags=str(pkt[TCP].flags)) #TCP has SYN, SYN-ACK, ACK flags
    
    if UDP in pkt:
        return ParsedPacket(**base, protocol="UDP",src_port=pkt[TCP].sport,dst_port=pkt[TCP].dport) #UDP is connectionless and stateless

    if ICMP in pkt:
        return ParsedPacket(**base, protocol = "ICMP",icmp_type=pkt[icmp].type
                            ,icmp_flags=pkt[TCP].code)
