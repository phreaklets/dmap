# dmap
Minimalist network scanner

I was frustrated one day with nmap not doing exactly what I wanted and wanted to play around a little bit with scapy.

##LAN scanning
I find the best results are to just do an ARP sweep of the network and then TCP SYN scan the discovered hosts.
E.g., `dmap -a -s 192.168.1.0/24`

##WAN scanning
Since ARP sweeps are not viable for WAN scanning, dmap has ICMP ping and TCP ping options for scanning hosts outside
of the local broadcast domain.
E.g., `dmap -p -s 45.33.32.156` or `dmap -t -s 45.33.32.156`

Sometimes it's fun to see the different results, so you can do: `dmap -a -p 192.168.1.0/24` or
`dmap -a -t 192.168.1.0/24`

The code is extremely rough'n'ready, so apologies for that. It's also extremely slow, as I haven't added multiprocessing
support yet. It uses netaddr, docopts, scapy, clint and netifaces to get the job done. Most functions require access to
privileged system functions such as sending/receiving ARP traffic so you'll have to run it as root.
