from scapy.all import *
from sympy import N

ip_addr = '172.16.0.90'
ports = range(8880, 8900, 1)


def print_ports(port, state):
	print("%s | %s" % (port, state))

# syn scan
def syn_scan(target, ports):
	print("syn scan on, %s with ports %s" % (target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port,
		          flags="S"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:    #20 = RA = 0x14
                    # RA means port close.
					print_ports(port, "Closed")
				elif pkt[TCP].flags == 18:  # 18 = SA = 0x12
                    # SA means port open.
					print_ports(port, "Open")
				else:
					print_ports(port, "TCP packet resp / filtered")
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pkt.summary())
		else:
			print_ports(port, "Unanswered")


# udp scan
def udp_scan(target, ports):
    print("udp scan on, %s with ports %s" % (target, ports))
    for port in ports:
        pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
        if pkt is None:
            print_ports(port, "Open / filtered")
        else:
            if pkt.haslayer(ICMP) and int(pkt.getlayer(ICMP).code) == 3:
                # ICMP.code = port-unreachable
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
                print_ports(port, "Closed")
            elif pkt.haslayer(UDP):
                print('udp')
                print_ports(port, "Open / filtered")
            else:
                print_ports(port, "Unknown")
                print(pkt.summary())

# xmas scan
def xmas_scan(target, ports):
	print("Xmas scan on, %s with ports %s" %(target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
		if pkt is not None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					print_ports(port, "Closed")
				else:
					print_ports(port, "TCP flag %s" % pkt[TCP].flag)
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pkt.summary())
		else:
			print_ports(port, "Open / filtered")

        

# result = pscan_tcp_syn(IP_addr, ports)
# print(result)
udp_scan(ip_addr, ports)
