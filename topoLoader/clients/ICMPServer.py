#! /usr/bin/env python

from HostBehaviour import HostModule
import sys
import SocketServer
import socket
import struct

class RequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        self.packet, self.socket = self.request
        icmp_header = self.packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        print "type: [" + str(type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "] sequence_num: [" +  str(sequence/256) + "]"

class Server(SocketServer.BaseServer):
    address_family = socket.AF_INET
    socket_type = socket.SOCK_RAW
    proto = socket.IPPROTO_ICMP
    request_queue_size = 5
    allow_reuse_address = False
    max_packet_size = 1508
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        SocketServer.BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.socket = socket.socket(self.address_family, self.socket_type, self.proto)
        self.socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except:
                self.server_close()
                raise

    def server_bind(self):
        if self.allow_reuse_address:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

    def server_close(self):
        self.socket.close()

    def fileno(self):
        return self.socket.fileno()

    def get_request(self):
        data, client_addr = self.socket.recvfrom(self.max_packet_size)
        return (data, self.socket), client_addr

    def server_activate(self):
        pass

    def shutdown_request(self, request):
        self.close_request(request)

    def close_request(self, request):
        pass

class ICMPServer(HostModule):
	def __init__(self, *args):
		super(ICMPServer, self).__init__(*args)
		self.RequestHandler = RequestHandler
		self.Server = Server

if __name__ == '__main__':
	selfIPAddress = sys.argv[1]
    selfPort = int(sys.argv[2])
    targetIPAddress = sys.argv[3]
    targetPort = int(sys.argv[4])
    trafficClass = sys.argv[5]

	host = ICMPServer(selfIPAddress, int(selfPort), targetIPAddress, int(targetPort), trafficClass)
    
	host.serverExecute()
