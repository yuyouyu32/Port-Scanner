import click
from Scanner import *
from Attacker import *

SCAN_METHOD = {'tcp': TCPConnScan, 'syn': TCPSynScan, 'xmas': TCPXmasScan, 'fin': TCPFinScan,
               'null': TCPNullScan, 'ack': TCPAckScan, 'win': TCPWindowScan, 'udp': UDPScan}

ATTACK_METHOD = {'synflood': SYNFlood}

@click.command()
@click.option('--scan/--no-scan', '-S', default=False, help='Scanner')
@click.option('--attack/--no-attack', '-A', default=False, help='Attacker')
@click.option('--ip', '-i', default='172.16.0.90', type=str, help='Destination IP of the port scanner or attack program.')
@click.option('--sport', '-s', default=8880, type=int, help='The starting port of the port scanner.')
@click.option('--eport', '-e', default=8890, type=int, help='The ending port of the port scanner.')
@click.option('--timeout', '-t', default=2, type=int, help='Set the timeout.')
@click.option('--method', '-m', default='syn', type=str, help='Port scanning or network attack methods.')
@click.option('--prot', '-p', default=8080, type=int, help='Attack aim port.')
def ymap(scan, attack, ip, sport, eport, method, timeout, port):
    if scan and attack:
        click.secho(
            'ERROR: Please Choose One Mode!(-S for Scan, -A for Attack)!', fg='red', bold=True)
        return
    elif scan:
        if method not in SCAN_METHOD.keys():
            click.secho(
                'ERROR: Please enter a legal scan method!(tcp, syn, xmas, fin, null, ack, win, udp)!', fg='red', bold=True)
            return
        else:
            scan_method = SCAN_METHOD[method](target=ip, timeout=timeout)
            scan_method.scan(range(sport, eport + 1))
    else:
        if method not in Attack_METHOD.keys():
            click.secho(
                'ERROR: Please enter a legal scan method(synflood)!', fg='red', bold=True)
            return
        else:
            att_method = ATTACK_METHOD[method](target=ip, port=port)
            att_method.attack()


if __name__ == '__main__':
    ymap()
