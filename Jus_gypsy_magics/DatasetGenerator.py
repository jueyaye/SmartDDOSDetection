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
	for packet in packets:
		print packet	
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
						subPacket.used = True;
						currentList.append(subPacket);

			connections.append(currentList.copy());

	return connections;



def separateIPsToTransport(IPConnections):
	TCPPackets = []
	UDPPackets = []
	ICMPPackets = []
	OtherPackets = []

	for connection in IPConnections:
		for packet in connections:
			if (packet.haslayer(TCP)):
				TCPPackets.append(packet)
			elif (packet.haslayer(UDP)):
				UDPPackets.append(packet)
			elif (packet.haslayer(ICMP)):
				ICMPPackets.append(packet)
			else:
				OtherPackets.append(packet)

	return {'TCP': TCPPackets, 'UDP': UDPPackets, 'ICMP': ICMPPackets, 'Other': OtherPackets}


def separateUDPPortPairs(UDPPackets):
	portPairs = []
	
	for packet in UDPPackets:
		packet.used = False;


	for packet in UDPPackets:
		

		currentPair = [packet[UDP].sport, packet[UDP].dport]
		#	print currentPair

		currentList = []

		for subPacket in packets:
			if (subPacket[UDP].sport == currentPair[0] and subPacket[UDP].dport == currentPair[1]):
				subPacket.used = True;
				currentList.append(subPacket);

		portPairs.append(currentList.copy());

	return portPairs;
		
def separateTCPPortPairs(TCPPackets):
	portPairs = []
	
	for packet in TCPPackets:
		packet.used = False;


	for packet in TCPPackets:
		

		currentPair = [packet[TCP].sport, packet[TCP].dport]
		#	print currentPair

		currentList = []

		for subPacket in packets:
			if (subPacket[TCP].sport == currentPair[0] and subPacket[TCP].dport == currentPair[1]):
				subPacket.used = True;
				currentList.append(subPacket);

		portPairs.append(currentList.copy());

	return portPairs;


def separateICMPToUnique(ICMPPackets):
	sequenceNumbers = []
	uniqueConnections = {}

	for packet in ICMPPackets:
		if not (packet[ICMP].seq in sequenceNumbers):
			uniqueConnections[packet[ICMP].seq] = []
		uniqueConnections[packet[ICMP].seq].append(packet)

	return uniqueConnections.values()



def separateTCPPortPairToUnique(portPair):
	
	uniqueConnections = []

	for packet in portPair:
		recording = true;
		connection = []

		flags = packet['TCP'].flags
		if flags & SYN:
			recording = true;

		if recording == true:
			connection.append(packet)

		if flags & FIN:
			recording = false
			uniqueConnections.append(connection.copy())
			connection = []
				
	return uniqueConnections

def identifyTCPApplication(connection):
	for packet in connection:
		return


#readPCAP("test.pcap")

print len(separateConnectionIPs(readPCAP("test.pcap")));

b = ICMP();


readPCAP

