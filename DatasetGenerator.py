#! /usr/bin/env python
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


from scapy.all import *

a = IP(dst="192.166.1.1")/TCP();


def readPCAP(filename):
	packets = rdpcap(filename)
	#for packet in packets:
	#	print packet.haslayer(IP)
	#	if packet.haslayer(IP):
		#	print packet[IP].dst
	return packets



def separateConnectionIPs(packets):
	connections = []
	for packet in packets:
		packet.used = False;
	
	for packet in packets:
		

		if (packet.haslayer(IP) and packet.used == False):
			currentPair = [packet[IP].src, packet[IP].dst]
		#	print currentPair

			currentList = []

			for subPacket in packets:
				if subPacket.haslayer(IP):
					if (subPacket[IP].src == currentPair[0] and subPacket[IP].dst == currentPair[1]):
					#	print "SRHEK"
					#	print subPacket;
						subPacket.used = True;
						currentList.append(subPacket);

			connections.append(currentList);

	return connections;

		
def separateIPsToTCP(IPConnections):
	TCPConnections = []

	for connection in IPConnections:
		for packet in connection:
			packet.used = False;

		if (packet.haslayer(TCP) and packet.used == False):
			currentPair = [packet[TCP].sport, packet[TCP].dport]
		#	print currentPair

			currentList = []

			for subPacket in packets:
				if subPacket.haslayer(TCP):
					if (subPacket[TCP].sport == currentPair[0] and subPacket[TCP].dport == currentPair[1]):
					
						subPacket.used = True;
						currentList.append(subPacket);

			TCPConnections.append(currentList);



	return TCPConnections;

def separateTCPToUnique(TCPConnection):
	uniqueConnections = []

	for connection in TCPConnection:
		recording = true;

		index = 0;
		uniqueConnections.append([])

		for packet in connection:
			flags = packet['TCP'].flags
			if flags & SYN:
				recording = true;

			if recording == true:
				uniqueConnections[index].append(packet)

			if flags & FIN:
				recording = false
				index += 1
				





#readPCAP("test.pcap")

print len(separateConnectionIPs(readPCAP("test.pcap")));



print a.dst
print a[TCP].SYN