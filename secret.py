#!/usr/bin/env python
#  Copyright 2016 Ravi Nihalani <ravinihalani@Ravis-MacBook-Air.local>

import sys
import binascii
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# later make the below dynamic for last msg - first upload and see
#~ print sys.argv[1:]
ip_address=sys.argv[1]
v_interface=sys.argv[2]
type_input=sys.argv[3]
msg=""
for x in range(4,len(sys.argv)):
	if x==4:
		msg = sys.argv[x]
	else:
		msg = msg + " " +sys.argv[x]
	#~ print "Packet is holding character=", x,sys.argv[x]

print msg
i=IP()
i.dst=ip_address
if type_input == "0":
	for x in range(len(msg)):
		print "Packet is holding character=", msg[x]
		#~ print "raviiiii hex",hex(24832)
		i.id=int(format(ord(msg[x]), '#010b')[2:] + '00000000',2)
		#~ print "Identification field is holding ",msg[x]," is ",format(ord(msg[x]), '#010b')[2:] + '00000000'
		i.frag=int('00000' + format((x), '#010b')[2:],2)
		#~ i.frag=ChangeHex(24832)
		send(i/ICMP()/"TEST\n",iface=v_interface)
		#~ i.display()
		
	print "Last packet sending --->"
	i.id=int('0000000000000000',2)
	print "frag is set to ",'10000' + format(len(msg), '#010b')[2:]
	i.frag=int('10000' + format(len(msg), '#010b')[2:],2)
	send(i/ICMP()/"TEST\n",iface=v_interface)
	#~ i.display()
	print "packet sent via 0: ICMP Echo Request Message"
elif type_input == "1":
	t = TCP()
	t.dport = 80
	for x in range(len(msg)):
		print "Packet is holding character=", msg[x]
		i.id=int(format(ord(msg[x]), '#010b')[2:] + '00000000',2)
		#~ print "Identification field is holding ",msg[x]," is ",format(ord(msg[x]), '#010b')[2:] + '00000000'
		i.frag=int('00000' + format((x), '#010b')[2:],2)
		send(i/t/"TEST\n",iface=v_interface)
		#~ i.display()
		
	print "Last packet sending --->"
	i.id=int('0000000000000000',2)
	print "frag is set to ",'10000' + format(len(msg), '#010b')[2:]
	i.frag=int('10000' + format(len(msg), '#010b')[2:],2)
	send(i/t/"TEST\n",iface=v_interface)
	#~ i.display()
	print "packet/s successfully sent via 1: TCP SYN packet to port 80"
elif type_input == "2":
	u = UDP()
	u.dport = 53
	for x in range(len(msg)):
		print "Packet is holding character=", msg[x]
		i.id=int(format(ord(msg[x]), '#010b')[2:] + '00000000',2)
		#~ print "Identification field is holding ",msg[x]," is ",format(ord(msg[x]), '#010b')[2:] + '00000000'
		i.frag=int('00000' + format((x), '#010b')[2:],2)
		send(i/u/"TEST\n",iface=v_interface)
		#~ i.display()
		
	print "Last packet sending --->"
	i.id=int('0000000000000000',2)
	print "frag is set to ",'10000' + format(len(msg), '#010b')[2:]
	i.frag=int('10000' + format(len(msg), '#010b')[2:],2)
	send(i/u/"TEST\n",iface=v_interface)
	#~ i.display()
	print "packet successfully sent via 2: UDP packet to port 53"
else:
	for x in range(len(msg)):
		print "Packet is holding character=", msg[x]
		i.id=int(format(ord(msg[x]), '#010b')[2:] + '00000000',2)
		#~ print "Identification field is holding ",msg[x]," is ",format(ord(msg[x]), '#010b')[2:] + '00000000'
		i.frag=int('00000' + format((x), '#010b')[2:],2)
		send(i/ICMP()/"TEST\n",iface=v_interface)
		#~ i.display()
		
	print "Last packet sending --->"
	i.id=int('0000000000000000',2)
	print "frag is set to ",'10000' + format(len(msg), '#010b')[2:]
	i.frag=int('10000' + format(len(msg), '#010b')[2:],2)
	send(i/ICMP()/"TEST\n",iface=v_interface)
	i.display()
	print "incorrect type selected hence packet successfully sent via ICMP by default"
