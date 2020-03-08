#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import httplib
import time

class HTTPClient(HostModule):
	def __init__(self, *args):
		super(HTTPClient, self).__init__(*args)

	def clientBehaviour(self):
		conn = httplib.HTTPConnection(self.IPAddr, self.port);
	#	print "OUTPUT "
	#	print self.IPAddr

		conn.request("GET", "/");
		res = conn.getresponse();
		print res.status, res.reason
		data = res.read();
		print data		
		time.sleep(1);

if __name__ == '__main__':
	IPAddress = sys.argv[1]
	port = int(sys.argv[2])
	print "DA BEARS"
	host = HTTPClient(IPAddress, int(port))
	host.clientExecute()
