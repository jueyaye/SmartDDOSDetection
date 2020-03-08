#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import BaseHTTPServer

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html; charset=utf-8')
		self.end_headers()
		self.wfile.write("Message Content\r\n")

class HTTPServer(HostModule):
	def __init__(self, *args):
		super(HTTPServer, self).__init__(*args)
		self.RequestHandler = RequestHandler
		self.Server = BaseHTTPServer.HTTPServer

if __name__ == '__main__':
	IPAddress = sys.argv[1]
	port = int(sys.argv[2])
	print "HELLO WORLD"
	host = HTTPServer(IPAddress, int(port))
	host.serverExecute()
