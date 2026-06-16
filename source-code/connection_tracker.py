from collections import defaultdict, deque
from datetime import datetime,timedelta
from packet_parser import ParsedPacket, parse 
WINDOW_SECONDS = 60

class ConnectionTracker:
    def __init__(self):
        # src_ip -> deque of (timestamp, dst_port) for TCP SYNs
        self.syn_attempts : dict[str,deque] = defaultdict(deque)
        # src_ip -> deque of timestamps of all packets
        self.packet_times: dict[str,deque] = defaultdict(deque)
        # src_ip -> set of unique dst_ports contacted in window
        self.port_contacted : dict[str, set] = defaultdict(set)


    def record(self, pkt: ParsedPacket):
        now = pkt.timestamp
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        src = pkt.src_ip

        #Slide the window - drop old entries
        self._expire(self.packet_times[src], cutoff)
        self.packet_times[src].append(now)

        if pkt.protocol = "TCP" and "SYN" in pkt.tcp_flags and "ACK" not in pkt.tcp_flags:
            self._expire(self.syn_attempts[src], cutoff, keyed=True)
            self.syn_attempts[src].append((now, pkt.dst_port))
            self.ports_contacted[src].add(pkt.dst_port)


    def syn_count(self, src_ip : str) -> int:
        return len(self.syn_attempts.get(src_ip, []))

    def unique_ports(self, src_ip : str) -> int:
        return len(self.ports_connected.get(src_ip, set()))

    def packet_rate(self, src_ip : str) -> int:
        return len(self.packet_times.get(src_ip, []))

    def _expire(self, dq : deque, cutoff, keyed=False):
        while dq and (dq[0][0] if keyed else dq[0]) < cutoff:
            dq.popleft()
