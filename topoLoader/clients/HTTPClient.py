#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import httplib
import time

class HTTPClient(HostModule):
	def __init__(self, *args):
		super(HTTPClient, self).__init__(*args)

	def clientBehaviour(self):
		conn = httplib.HTTPConnection(self.targetIPAddr, self.targetPort, source_address=(self.selfIPAddr, self.selfPort));
		conn.request("GET", "/");
		res = conn.getresponse();
		print res.status, res.reason
		data = res.read();
		print data		
		time.sleep(1);

if __name__ == '__main__':
	selfIPAddress = sys.argv[1]
	selfPort = int(sys.argv[2])
	targetIPAddress = sys.argv[3]
	targetPort = int(sys.argv[4])
	trafficClass = sys.argv[5]

	host = HTTPClient(selfIPAddress, int(selfPort), targetIPAddress, int(targetPort), trafficClass)
	host.clientExecute()
