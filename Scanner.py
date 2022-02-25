import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from prettytable import PrettyTable

#############################################################################
# ICMP Codes (Type 3) Used to determine filtering:                          #
# 1  Host Unreachable                                                       #
# 2  Protocol Unreachable                                                   #
# 3  Port Unreachable                                                       #
# 9  Communication with Destination Network is Administratively Prohibited  #
# 10  Communication with Destination Host is Administratively Prohibited    #
# 13  Communication Administratively Prohibited                             #
#############################################################################

__all__ = ["TCPConnScan", "TCPSynScan", "TCPXmasScan", "TCPFinScan",
           "TCPNullScan", "TCPAckScan", "TCPWindowScan", "UDPScan"]


def print_banner():
    bannerTxt = """                                
 __   __ __  __    ___      ___  
 \ \ / /|  \/  |  /   \    | _ \ 
  \ V / | |\/| |  | - |    |  _/ 
   |_|  | |  | |  | | |    | |
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'                
Contact : yuyeyong [at] shu [dot] edu [dot] cn
Github  : https://github.com/yuyouyu32/Port-Scanner
   	"""
    print(bannerTxt)


class _PortScanner:
    """
    Base PortScanner object to inherit from.
    """
    __scanner__ = "Base Scanner"

    def __init__(self, target, timeout=2):
        self._target = target
        self._timeout = timeout
        self._results = {}
        self.table = PrettyTable(['IP', 'Port', 'State'])

    def set_target(self, new_target):
        self._target = new_target

    def scan(self, ports):
        print("%s results for %s" % (self.__scanner__, self._target))
        print("PORT\tSTATE")
        for port in list(ports):
            self._scan_port(port)
        self._report()

    def _scan_port(self, port):
        raise NotImplementedError()

    def _report(self):
        scanned = len(self._results)
        open_ports = 0
        for value in self._results.values():
            if type(value) is str and value == "Open":
                open_ports += 1
        print_banner()
        print(self.table)
        print("Scanned %d ports, of which %d were opened." %
              (scanned, open_ports))

    def _record_port_state(self, Port, State):
        print("%s\t%s" % (Port, State))
        self._results[Port] = State
        self.table.add_row([self._target, Port, State])


class TCPConnScan(_PortScanner):
    __scanner__ = "TCP Connect Scan"

    def _scan_port(self, port):
        '''
        ###[ IP ]### 
            version   = 4
            ihl       = 5
            tos       = 0x0
            len       = 44
            id        = 0
            flags     = DF
            frag      = 0
            ttl       = 63
            proto     = tcp
            chksum    = 0x8534
            src       = 172.16.0.90
            dst       = 10.8.0.38
            \options   \
        ###[ TCP ]### 
            sport     = 8881
            dport     = 36798
            seq       = 46541985
            ack       = 1
            dataofs   = 6
            reserved  = 0
            flags     = SA
            window    = 64240
            chksum    = 0x51c
            urgptr    = 0
            options   = [('MSS', 1358)]
        '''
        src_port = RandShort()
        # Sends a SYN
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags="S"), timeout=self._timeout, verbose=False)

        if resp is None:
            self._record_port_state(port, 'Closed')
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:    # 18 = SA = 0x12
                send_rst = sr(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                              flags="AR"), timeout=self._timeout, verbose=False)
                self._record_port_state(port, 'Open')

            elif resp.getlayer(TCP).flags == 0x14:    # 20 = RA = 0x14
                self._record_port_state(port, 'Closed')


class TCPSynScan(_PortScanner):
    __scanner__ = "TCP SYN Scan"

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags="S"), timeout=self._timeout, verbose=False)

        if resp is None:
            self._record_port_state(port, 'Unanswered')

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                rst = sr(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                         flags="R"), timeout=self._timeout, verbose=False)
                self._record_port_state(port, 'Open')

            elif resp.getlayer(TCP).flags == 0x14:
                self._record_port_state(port, 'Closed')
            else:
                self._record_port_state(port, 'TCP packet resp / filtered')
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and \
               int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:  # Destination Host Unreachable
                self._record_port_state(port, 'ICMP resp / filtered')
        else:
            self._record_port_state(port, 'Unknown resp')
            print(resp.summary())


class TCPNullScan(_PortScanner):
    __scanner__ = "TCP Null Scan"

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags=""), timeout=self._timeout, verbose=False)
        if resp is None:
            self._record_port_state(port, 'Open|Filtered')

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:    # 20 = RA = 0x14
                self._record_port_state(port, 'Closed')

        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and \
               int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:  # Destination Host Unreachable
                self._record_port_state(port, 'Filtered')


class TCPFinScan(_PortScanner):
    __scanner__ = "TCP FIN Scan"

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags="F"), timeout=self._timeout, verbose=False)
        if resp is None:
            self._record_port_state(port, 'Open|Filtered')

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:    # 20 = RA = 0x14
                self._record_port_state(port, 'Closed')

        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and \
               int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:  # Destination Host Unreachable
                self._record_port_state(port, 'Filtered')


class TCPXmasScan(_PortScanner):
    __scanner__ = "TCP Xmas Scan"

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags="FPU"), timeout=self._timeout, verbose=False)
        if resp is None:
            self._record_port_state(port, 'Open|Filtered')

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:    # 20 = RA = 0x14
                self._record_port_state(port, 'Closed')
            else:
                self._record_port_state(port, resp[TCP].flags)
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and \
               int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:  # Destination Host Unreachable
                self._record_port_state(port, 'Filtered')
        else:
            self._record_port_state(port, 'Unknown resp')
            print(resp.summary())


class TCPAckScan(_PortScanner):
    __scanner__ = "TCP ACK Scan"

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags="A"), timeout=self._timeout, verbose=False)
        if resp is None:
            self._record_port_state(port, 'Filtered')

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x4:    # 4 = R = 0x4
                # TTL < 64 -> Open; TTL > 64 -> Closed; TTL ==64 Unknow.
                if int(resp.getlayer(IP).ttl) < 64:
                    self._record_port_state(port, 'Open')
                elif int(resp.getlayer(IP).ttl) > 64:
                    self._record_port_state(port, 'Closed')
                else:
                    self._record_port_state(port, 'Unfiltered')
            else:
                self._record_port_state(port, resp[TCP].flags)
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and \
               int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:  # Destination Host Unreachable
                self._record_port_state(port, 'Filtered')
        else:
            self._record_port_state(port, 'Unknown resp')
            print(resp.summary())


class TCPWindowScan(_PortScanner):
    __scanner__ = "TCP Window Scan"

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port,
                   flags="A"), timeout=self._timeout, verbose=False)
        if resp is None:
            self._record_port_state(port, 'Unanswered')

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).window == 0:
                self._record_port_state(port, 'Closed')
            elif resp.getlayer(TCP).window > 0:
                self._record_port_state(port, 'Open')
            else:
                self._record_port_state(port, resp[TCP].flags)
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and \
               int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:  # Destination Host Unreachable
                self._record_port_state(port, 'Filtered')
        else:
            self._record_port_state(port, 'Unknown resp')
            print(resp.summary())


class UDPScan(_PortScanner):
    __scanner__ = "UDP Scan"
    '''
    ###[ IP ]### 
        version   = 4
        ihl       = 5
        tos       = 0xc0
        len       = 56
        id        = 44972
        flags     = 
        frag      = 0
        ttl       = 63
        proto     = icmp
        chksum    = 0x14c1
        src       = 172.16.0.90
        dst       = 10.8.0.38
        \options   \
    ###[ ICMP ]### 
        type      = dest-unreach
        code      = port-unreachable
        chksum    = 0xb3ae
        reserved  = 0
        length    = 0
        nexthopmtu= 0
        unused    = ''
    ###[ IP in ICMP ]### 
        version   = 4
        ihl       = 5
        tos       = 0x0
        len       = 28
        id        = 1
        flags     = 
        frag      = 0
        ttl       = 63
        proto     = udp
        chksum    = 0xc538
        src       = 10.8.0.38
        dst       = 172.16.0.90
            \options   \
    ###[ UDP in ICMP ]### 
        sport     = 8885
        dport     = 8885
        len       = 8
        chksum    = 0x3dc
    '''

    def _scan_port(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self._target)/UDP(sport=src_port,
                   dport=port), timeout=self._timeout, verbose=False)
        if resp is None:
            self._record_port_state(port, "Open|Filtered")
        elif resp.haslayer(UDP):
            self._record_port_state(port, 'Open')
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3:
                # Destination Host Unreachable
                if int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    self._record_port_state(port, 'Filtered')
                elif int(resp.getlayer(ICMP).code) == 3:
                    # ICMP.code = port-unreachable
                    self._record_port_state(port, 'Closed')
        else:
            self._record_port_state(port, 'Unknown resp')
            print(resp.summary())
