#! /usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import info, setLogLevel
from mininet.cli import CLI

from time import time, sleep
from select import poll, POLLIN
from subprocess import Popen, PIPE

class SingleSwitchTopo(Topo):
	def build(self, n=2):
		switch = self.addSwitch('s1')

		for h in range(n):
			host = self.addHost('h%s' % (h+1))
			self.addLink(host, switch)


def simpleTest():
	topo = SingleSwitchTopo(n=2)
	net = Mininet(topo)
	net.start()



	h1, h2 = net.get('h1', 'h2')

	print h1.IP
	print h2.IP
	print 'starting test'
	#h1.cmd('while true; do date; sleep 1; done > date.out &')


	net.pingAll()

	h1.cmd('sudo ./HTTPServer.py 10.0.0.1 80 10 10 TCP IPv4 &' )
	h2.cmd('sudo ./HTTPClient.py 10.0.0.2 8000 10 10 TCP IPv4 &' )

	sleep(100)

	
	print 'stopping test'
	print "Reading output"
	f = open('rcvr.out')

	writef = open('boys.txt', "w")

	lineno = 1
	for line in f.readlines():
		print "%d: %s" % (lineno, line.strip())

		writef.write("%d: %s\n" % (lineno, line.strip()))

		lineno+=1
	f.close()

	writef.close()
	
	net.stop()


def deployTest():
	topo = SingleSwitchTopo(n=4)
	net = Mininet(topo)
	net.start()
	CLI(net)






if __name__ == '__main__':
	deployTest()
#	simpleTest();
