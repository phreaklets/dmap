#!/usr/bin/env python3
import time
import requests
import nmap
import json
import sys
import click
import netifaces as ni
import logging

from netaddr import IPNetwork, IPAddress
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

iface_scapy = ""
timeout_scapy = 0.3

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
def main():
    """
    Minimalist network scanner
    """
    pass

def arpsweep_multiprocessing(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = str(ip)), timeout = timeout_scapy, iface=iface_scapy, inter=0.1, verbose=False)
    for snd,rcv in ans:
        mac = rcv.sprintf(r"%Ether.src%")
        ip = rcv.sprintf(r"%ARP.psrc%")

        if mac is not None and ip is not None:
            return ({'mac_addr':mac,'ip_addr':ip})
    return None

def is_netrange(cidr):
    try:
        tmp = IPNetwork(cidr)
        return True
    except Exception as e:
        return False

def vendor_lookup(ethsrc):
    vendor_eth = ethsrc.replace(":", "-")
    url = "http://api.macvendors.com/{}".format(vendor_eth)
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        if response is not None:
            return response.text
    except requests.exceptions.RequestException or requests.exceptions.ConnectionError:
        print("Requests error occured")
    return None
    
@main.command()
@click.option('--json', '-j', 'json_', is_flag=True)
@click.option('--iface', '-i', 'iface_', default="eth0")
@click.option('--timeout', '-t', 'timeout_', default=0.3)
@click.argument('net_')
def arp(net_, iface_, timeout_, json_):
    t = Terminal()
    if not is_netrange(net_):
        click.echo("Invalid netrange: {}".format(net_))
        sys.exit(1)
        
    netr = IPNetwork(net_)
    results = {}
    
    global iface_scapy
    iface_scapy = iface_

    if timeout_ != 0.3:
        global timeout_scapy
        timeout_scapy = float(timeout_)
        
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
            vendor = vendor_lookup(result['mac_addr'])
            print(t.blue("IP addr"), t.yellow("{0:<15}".format(result['ip_addr'])), t.blue("MAC addr"), t.yellow("{0:<17}".format(result['mac_addr'])), t.blue("Vendor"), t.yellow(vendor))
            time.sleep(1)
            
if __name__ == "__main__":
    main()
