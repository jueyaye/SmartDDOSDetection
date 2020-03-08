#! /usr/bin/env python

from scapy.all import send,sr1,IP,ICMP,UDP,Ether
from random import randint
from HostBehaviour import HostModule
import time
import sys

class HTTPHost(HostModule):
	
	def __init__(self, *args):
		super(HTTPHost, self).__init__(*args)

	def serverBehaviour(self):
		print self.IPAddr
		self.receive(1024, False);

		print "CONNECTION"

		data = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

		tself.sendApplication(data)

	
	def clientExecute(self):
		data = 'GET data/data.txt HTTP/1.1\r\n Host: www.host.com\r\n\r\n'

		self.sendApplication(data)

		self.receive(1024, False)





if __name__ == '__main__':
	IPAddr = sys.argv[1]
	port = sys.argv[2]
	startupDelay = sys.argv[3]
	frequency = sys.argv[4]
	transportProtocol = sys.argv[5]
	mode = sys.argv[6]

	writef = open('rcvr' + port + '.out', "w")
	writef.write("BOI      ")
	writef.write(IPAddr)
	writef.flush()
	writef.close()
	
	host = HTTPHost(IPAddr, int(port), startupDelay, frequency, transportProtocol)
	if (mode == 'server'):
		host.serverExecute()
	elif (mode == 'client'):
		host.clientExecute()