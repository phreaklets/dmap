#!/usr/bin/env python3
import json
import sys
import requests
import click
import netifaces as ni
import pprint
import sys
from netaddr import IPNetwork, IPAddress
import logging
import imp
from scapy.config import conf  
conf.ipv6_enabled = False
from scapy.all import sr,srp,Ether,ARP,IP,ICMP,TCP,sr1,RandShort,conf #Import needed modules from scapy
# turn off those irritating IPv6 warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from multiprocessing import Pool

from pygments import highlight, lexers, formatters
from pprint import pprint
from blessed import Terminal

__author__ = "Phreaklets"

@click.group()
def main():
    """
    Minimalist network scanner
    """
    pass

def arpsweep_multiprocessing(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = str(ip)), timeout = 0.1,iface="eth0",inter=0.1,verbose=False)
    for snd,rcv in ans:
        mac = rcv.sprintf(r"%Ether.src%")
        ip = rcv.sprintf(r"%ARP.psrc%")

        if mac is not None and ip is not None:
            return ({'mac_addr':mac,'ip_addr':ip})
    return None

@main.command()
@click.option('--ip_range', help='IP range for scanning', required=True)
@click.option('--json', '-j', 'json_', is_flag=True)
@click.argument('command')
def scan(command, ip_range, json_):
    t = Terminal()
    netr = IPNetwork(ip_range)
    results = {}
    if command == 'arp':
        if not json_:
            print(t.cyan("Starting ARP sweep"))
        p = Pool(64)

        try:
            temp_results = p.map(arpsweep_multiprocessing, list(netr))
            results = [_f for _f in temp_results if _f]
        except KeyboardInterrupt:
            sys.exit()
            p.terminate()
            p.join()
        p.close()
        p.join()

    if json_:
        json_output=json.dumps({'live_hosts':results})
        print(json_output)
    else:
        for result in results:
            print(t.blue("MAC addr"), t.yellow("{}".format(result['mac_addr'])), t.blue("IP addr"), t.yellow("{}".format(result['ip_addr'])))
            
if __name__ == "__main__":
    main()
