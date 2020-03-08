#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import httplib
import time
from scapy.all import *
import random

class ICMPClient(HostModule):
	def __init__(self, *args):
		super(ICMPClient, self).__init__(*args)

	def clientBehaviour(self):
		id = random.randint(10000,65000)
		for i in range(1,11):
			packet = IP(dst=self.IPAddr)/ICMP(seq=i, id=id)
			reply = sr1(packet)
			if not (reply is None):
				print reply.src, "responded"
			else:
				print "Timeout waiting for %s" % packet[IP].dst
			time.sleep(0.1);
		time.sleep(1);

if __name__ == '__main__':
	IPAddress = sys.argv[1]
	port = int(sys.argv[2])
	print "DA BEARS"
	host = ICMPClient(IPAddress, int(port))
	host.clientExecute()
