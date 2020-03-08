#! /usr/bin/env python

from scapy.all import send,sr1,IP,ICMP,UDP,Ether
from random import randint
import time
import socket
from thread import start_new_thread
import SocketServer

class HostBehvaiour(object):
	modules = {}

	

# this is a class users will create to be there modules
class HostModule(object):
	def __init__(self, IPAddr, port):
		self.IPAddr = IPAddr;
		self.port = port;


	def sendRaw(packet):
		send(packet)

	def sendAndReceiveRaw(packet):
		return sr1(packet)



	def receiveApplicationFull(self, bytes, timeout):
		if (timeout != False):
			self.sock.settimeout(timeout)	

		data, addr = sock.recvfrom(bytes)

		return (data, addr)


	# This gets called by client host
	def clientExecute(self):
	
		while True:
			self.clientBehaviour()
		print "AYY"
		return

	# This get called by serve rhost
	def serverExecute(self):
		HOST, PORT = self.IPAddr, self.port
		print PORT

		server = self.Server((HOST, PORT), self.RequestHandler)
		
		# Should put a shutdown timer in here at some point
		while True:
			server.handle_request()
		

	# This gets overwritten
	def serverBehvaiour():
		return

	# This gets overwritten
	def clientBehaviour(conn):
		return


