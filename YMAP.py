import click
from Scanner import *
from Attacker import *
from prettytable import PrettyTable


SCAN_METHOD = {'tcp': TCPConnScan, 'syn': TCPSynScan, 'xmas': TCPXmasScan, 'fin': TCPFinScan,
               'null': TCPNullScan, 'ack': TCPAckScan, 'win': TCPWindowScan, 'udp': UDPScan}

ATTACK_METHOD = {'synflood': SYNFlood, 'traceroute': TraceRoute, 'rstattack': RSTAttack,
                 'udpflood': UDPFlood}


@click.command()
@click.option('--scan/--no-scan', '-S', default=False, help='Scanner')
@click.option('--attack/--no-attack', '-A', default=False, help='Attacker')
@click.option('--methods/--no-methods', '-M', default=False, help='Show Methods table.')
@click.option('--threading/--no-threading', '-t', default=True, help='Use Threads Pool.')
@click.option('--ip', '-i', default='172.16.0.90', type=str, help='Destination IP of the port scanner or attack program.')
@click.option('--sport', '-s', default=8880, type=int, help='The starting port of the port scanner.')
@click.option('--eport', '-e', default=8890, type=int, help='The ending port of the port scanner.')
@click.option('--timeout', '-t', default=2, type=int, help='Set the timeout.')
@click.option('--method', '-m', type=str, help=f'Port scanning or network attack methods. Scanner methods {tuple(SCAN_METHOD.keys())}; Attacker methods {tuple(ATTACK_METHOD.keys())}.')
@click.option('--port', '-p', default=8080, type=int, help='Attack aim port.')
@click.option('--sourceport', '-sp', default=8080, type=int, help='Attack source port.')
@click.option('--sourceip', '-si', default='172.16.0.90', type=str, help='Source IP of the port scanner or attack program.')
@click.option('--sequence', '-seq', default=4065682361, type=int, help='Attack pakage sequence.')
def ymap(scan, attack, methods, threading, ip, sport, eport, method, timeout, port, sourceport, sourceip, sequence):
    if (scan and attack):
        click.secho(
            'ERROR: Please Choose One Mode!(-S for Scan, -A for Attack)!', fg='red', bold=True)
        return
    elif scan:
        if method not in SCAN_METHOD.keys():
            click.secho(
                f'ERROR: Please enter a legal scan method! {tuple(SCAN_METHOD.keys())}!', fg='red', bold=True)
            return
        else:
            scan_method = SCAN_METHOD[method](target=ip, timeout=timeout)
            scan_method.scan(range(sport, eport + 1), threading)
    elif attack:
        if method not in ATTACK_METHOD.keys():
            click.secho(
                f'ERROR: Please enter a legal scan method {tuple(ATTACK_METHOD.keys())}!', fg='red', bold=True)
            return
        else:
            att_method = ATTACK_METHOD[method](target=ip, port=port)
            if isinstance(att_method, RSTAttack):
                att_method.attack(source_ip=sourceip,
                                  source_port=sourceport, sequence=sequence)
            else:
                att_method.attack()
    else:
        if methods:
            methods_table = PrettyTable(['Class', 'Method', 'CLI'])
            for key, value in SCAN_METHOD.items():
                methods_table.add_row(['Scanner', value.__scanner__, key])
            for key, value in ATTACK_METHOD.items():
                methods_table.add_row(['Attacker', value.__attacker__, key]) 
            print(methods_table)
        else:
            click.secho(
            'ERROR: Please Choose One Mode!(-S for Scan, -A for Attack, -M for showing all methods)!', fg='red', bold=True)
            return
        
if __name__ == '__main__':
    ymap()
