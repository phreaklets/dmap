# dmap
**Minimalist network scanner**

I was frustrated one day with nmap not doing exactly what I wanted and wanted to play around a little bit with scapy.

## LAN scanning
ARP sweep of a net range.
`sudo ./dmap_v2.py scan arp --ip_range 192.168.1.0/24`
Dmap can also output its results in raw JSON format, suitable for piping into `jq` or similar for formatting:
`sudo ./dmap_v2.py scan arp --ip_range 192.168.1.0/24 --json | jq .`

Most functions require access to privileged system functions such as sending/receiving ARP traffic so you'll have to run it as root.
