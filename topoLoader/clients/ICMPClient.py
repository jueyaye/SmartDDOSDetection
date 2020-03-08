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
			packet = IP(dst=self.targetIPAddr)/ICMP(seq=i, id=id)/("class="+str(self.trafficClass)+"    ")
			reply = sr1(packet)
			if not (reply is None):
				print reply.src, "responded"
			else:
				print "Timeout waiting for %s" % packet[IP].dst
			time.sleep(0.1);
		time.sleep(1);

if __name__ == '__main__':
	selfIPAddress = sys.argv[1]
	selfPort = int(sys.argv[2])
	targetIPAddress = sys.argv[3]
	targetPort = int(sys.argv[4])
	trafficClass = sys.argv[5]

	# the regular client takes the address and port assigned to it
	# the attacker will also need to include the address and the port it wishes to target

	host = ICMPClient(selfIPAddress, int(selfPort), targetIPAddress, int(targetPort), trafficClass)
	host.clientExecute()
