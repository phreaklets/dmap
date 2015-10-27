import sys #Import needed modules
from datetime import datetime

try:
	interface = raw_input("[*] Enter Desired Interface: ")#Get interface to scan
	ips = raw_input("[*] Enter Range of IPs to Scan for: ")#Get IP or IP range to scan
except KeyboardInterrupt:
	print "\n[*] User Requested Shutdown"
	print "[*] Quitting..."
	sys.exit(1)
print "\n[*] Scanning... " #Initiate scanning
start_time = datetime.now() #Start clock for scan duration

from scapy.all import srp,Ether,ARP,conf #Import needed modules from scapy

conf.verb = 0 #Actually start scanning
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, 	iface=interface,inter=0.1)


print "MAC - IP\n" #Set up for result display
for snd,rcv in ans:
	print rcv.sprintf(r"%Ether.src% - %ARP.psrc%") #Display results
stop_time = datetime.now() #Stop clock for total duration
total_time = stop_time - start_time #Find total time
print "\n[*] Scan Complete!" #Comfirm scan completion
print ("[*] Scan Duration: %s" %(total_time)) #Display scan duration