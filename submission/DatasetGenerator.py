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
import re
import inspect

a = IP(dst="192.166.1.1")/TCP();



def readPCAP(filename):
	print "DARTH MEMIUS"
	print filename
	packets = rdpcap(filename)
		

	return packets




def separateNetworkLayer(packets):
	ARPPackets = []
	IPPackets = []
	ICMPPackets = []
	IPv6 = []
	other = []
	for packet in packets:
		if packet.haslayer(IP):
			IPPackets.append(packet)
		elif packet.haslayer(ARP):
			ARPPackets.append(packet)
		elif packet.haslayer(ICMP):
			ICMPPackets.append(packet)
		else:
			IPv6.append(packet)

	return {'ARP':ARPPackets, 'IP':IPPackets, 'ICMP':ICMPPackets, 'IPv6': IPv6, 'other': other}


def separateIPv6Connection(packets):
	connections = []
	for packet in packets:
		packet.used = False


	for packet in packets:
		if packet.used == True:
			continue;
		

		currentPair = [packet[IPv6].src, packet[IPv6].dst]
		
		
		currentList = []

		for subPacket in packets:
			if (subPacket[IPv6].src == currentPair[0] and subPacket[IPv6].dst == currentPair[1]):
				subPacket.used = True;
				currentList.append(subPacket);

		connections.append(currentList[:]);


	return connections;


def separateARPConnection(packets):
	connections = []

	for packet in packets:
		packet.used = False


	for packet in packets:
		newConnection = []
		if packet.used:
			continue

		if packet[ARP].op == 1:
			req = (packet[ARP].psrc, packet[ARP].pdst, packet[ARP].hwsrc, packet[ARP].hwdst)
			newConnection.append(packet)
			packet.used = True
		#	print req
		#	print '\n'
			for subPacket in packets:
			#	print repr((subPacket[ARP].psrc, subPacket[ARP].pdst, subPacket[ARP].hwsrc, subPacket[ARP].hwdst))
			
				if (subPacket[ARP].op == 2 and subPacket[ARP].pdst == req[0] and\
				 subPacket[ARP].hwdst == req[2] and subPacket[ARP].psrc == req[1]):
					newConnection.append(subPacket)
					subPacket.used = True

			connections.append(newConnection[:])
		


	return connections




def separateConnectionIPs(packets):
	connections = []
	for packet in packets:
		packet.used = False;
	
	for packet in packets:
		if packet.used:
			continue

		currentPair = (packet[IP].src, packet[IP].dst)

		currentList = []

		for subPacket in packets:
			if (subPacket[IP].src == currentPair[0] and subPacket[IP].dst == currentPair[1]):
				subPacket.used = True;
				currentList.append(subPacket);

		connections.append(currentList[:]);

	return connections;



def separateIPsToTransport(IPConnections):
	TCPPackets = []
	UDPPackets = []
	ICMPPackets = []
	OtherPackets = []

	for connection in IPConnections:
		for packet in connection:
	#		wrpcap("MEMES.pcap", packet, append=True)
			if (packet.haslayer(TCP)):
	#			wrpcap("MEMES2.pcap", packet, append=True)
			
				TCPPackets.append(packet)
			elif (packet.haslayer(UDP)):
				UDPPackets.append(packet)
			elif (packet.haslayer(ICMP)):
				ICMPPackets.append(packet)
			else:
				OtherPackets.append(packet)

	TCPPackets.sort(key=lambda x: x.time, reverse=False)
	UDPPackets.sort(key=lambda x: x.time, reverse=False)
	ICMPPackets.sort(key=lambda x: x.time, reverse=False)
	OtherPackets.sort(key=lambda x: x.time, reverse=False)

	return {'TCP': TCPPackets, 'UDP': UDPPackets, 'ICMP': ICMPPackets, 'Other': OtherPackets}


def separateUDPPortPairs(UDPPackets):
	portPairs = []
	
	for packet in UDPPackets:
		packet.used = False;

	i = True

	for packet in UDPPackets:
		

		currentPair = [packet[UDP].sport, packet[UDP].dport]
		#	print currentPair

		currentList = []

		for subPacket in UDPPackets:
			if (subPacket[UDP].sport == currentPair[0] and subPacket[UDP].dport == currentPair[1]):
				subPacket.used = True;
				currentList.append(subPacket);


		portPairs.append(currentList[:]);


	return portPairs;
		
def separateTCPPortPairs(TCPPackets):
	portPairs = []
	for packet in TCPPackets:
	#	print packet.time
		packet.used = False;

	i = True

	for packet in TCPPackets:
		if (packet.used):
			continue

		currentPair = (packet[TCP].sport, packet[TCP].dport)

		
		currentList = []

		for subPacket in TCPPackets:
			if (subPacket[TCP].sport == currentPair[0] and subPacket[TCP].dport == currentPair[1]) or \
			(subPacket[TCP].sport == currentPair[1] and subPacket[TCP].dport == currentPair[0]) :
				if (subPacket.used):
					continue
				subPacket.used = True;
				currentList.append(subPacket);




		portPairs.append(currentList[:]);

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
	recording = False;
	connection = []

	#uniqueConnections.append([])
	for packet in portPair:
		flags = packet['TCP'].flags
	#	print packet.time
				
		if (flags & SYN) != 0:
			recording = True;

		if recording == True:
			connection.append(packet)

		if (flags & FIN) != 0 and (flags & PSH) == 0:
			seq = packet['TCP'].seq
			ack = packet['TCP'].ack
			for subPacket in portPair:
				if (subPacket['TCP'].seq == ack) and (subPacket['TCP'].ack == (seq + 1)):
					connection.append(subPacket)
					break;
			recording = False
			uniqueConnections.append(connection[:])
			connection = []

		if (flags & RST) != 0:
			recording = False
			uniqueConnections.append(connection[:])
			connection = []

	if len(connection) > 0:
		uniqueConnections.append(connection[:])
				
	return uniqueConnections






def generateData(packets):
	uniqueConnections = []

	print "Network Separation"
	networkConnections = separateNetworkLayer(packets)

	

	print "ARP Connections"
	ARPConnections = separateARPConnection(networkConnections['ARP'])

	print "IPv6 Connections"
	IPv6Connections = separateIPv6Connection(networkConnections['IPv6'])

	print "IP Connections"
	IPConnections = separateConnectionIPs(networkConnections['IP'])

	
	print "TCP Separation"
	transportConnections = separateIPsToTransport(IPConnections)
	
	tcpPortPairs = separateTCPPortPairs(transportConnections["TCP"])
#	print "LEN"
#	print len(tcpPortPairs)
	a = 0
	for portPair in tcpPortPairs:
	#	print "PP"
		i = 0
			
		uniques = separateTCPPortPairToUnique(portPair)
		#for unique in uniques:
		#	print i
		#	for pack in unique:
		#		wrpcap('Unique' + str(i) +'_' + str(a) +'.pcap', pack, append=True)
			#	print pack.time
		#	i+=1
			

	#	uniques = portPair
		a+=1
		uniqueConnections.extend(uniques)
		#if a == 2:
		#	break
	
	print "UDP Separation"	
	udpPortPairs = separateUDPPortPairs(transportConnections["UDP"])

	uniqueConnections.extend(ARPConnections)
	uniqueConnections.extend(IPv6Connections)
	uniqueConnections.extend(udpPortPairs)

	print "ICMP Separation"	
	uniqueConnections.extend(separateICMPToUnique(transportConnections["ICMP"]))

	return uniqueConnections









def getDuration(connection):
	firstTime = -1
	lastTime = 0

	for packet in connection:
		if packet.time < firstTime or firstTime == -1:
			firstTime = packet.time
		
		if packet.time > lastTime:
			lastTime = packet.time

	return (lastTime - firstTime)

def getProtocolType(connection):
	if (connection[0].haslayer(TCP)):
		return "tcp"
	elif(connection[0].haslayer(UDP)):
		return "udp"
	elif(connection[0].haslayer(ICMP)):
		return "icmp"
	elif( connection[0].haslayer(IPv6) and (not connection[0].haslayer(TCP)) and (not connection[0].haslayer(UDP))):
		return "icmpv6"
	else:
		return "eth"

def isARP(packet):
	return packet.haslayer(ARP)

def isDHCP(packet):
	return packet.haslayer(DHCP)

def isHTTP(packet):
	if packet.haslayer(TCP):
		pattern = "^([A-Z]* \/[\S]* |)HTTP\/[1-2].[0-2]"
		payload = str(packet[TCP].payload)
		return (re.match(pattern, payload) is not None)
	else:
		return False
  

  #  print 'NEWPAY'
  #  print payload
    #pattern = 'HTTP'

   # return (payload.find('HTTP') != -1)
  #  

def isDNS(packet):
	return packet.haslayer(DNS)

def isMDNS(packet):
	if packet.haslayer(UDP):
		if packet[UDP].dport == 5353:
			return True
	return False

def isICMPv6(packet):
	return (packet.haslayer(IPv6) and (not packet.haslayer(TCP)) and (not packet.haslayer(UDP)))

def isTCP(packet):
	return packet.haslayer(TCP)

def isICMP(packet):
	return packet.haslayer(ICMP)

def getICMPType(packet):
	pType = packet[ICMP].type 
	if pType == 0 | pType == 8:
		return "ping"
	else:
		return "icmp"

def getService(connection):
	app = None
	for packet in connection:
		if isHTTP(packet):
			app = "http"
			break;
		elif isARP(packet):
			app = "arp"
			break;
		elif isDNS(packet):
			app = "dns"
			break;
		elif isICMPv6(packet):
			app = "icmpv6"
			break;
		elif isMDNS(packet):
			app = "mdns"
			break;
		elif isDHCP(packet):
			app = "dhcp"
			break;
		elif isICMP(packet):
			app = getICMPType(packet)
			break;
	
	if (app == None):
		if (packet.haslayer(TCP)):
			app = "tcp"
		elif (packet.haslayer(UDP)):
			app = "udp"
		else:
			app = "ukwn"
	return app

def getSrcBytes(connection):
	if connection[0].haslayer(IP):
		srcIP = connection[0][IP].src

		srcBytes = 0
		for packet in connection:
			if packet[IP].src == srcIP:
				srcBytes += len(str(packet))

		return srcBytes
	elif connection[0].haslayer(IPv6):
		srcIP = connection[0][IPv6].src

		srcBytes = 0
		for packet in connection:
			if packet[IPv6].src == srcIP:
				srcBytes += len(str(packet))
		return srcBytes
	else:
		srcIP = connection[0][Ether].src

		srcBytes = 0
		for packet in connection:
			if packet[Ether].src == srcIP:
				srcBytes += len(str(packet))
		return srcBytes



def getDstBytes(connection):
	if connection[0].haslayer(IP):
		
		dstIP = connection[0][IP].dst

		dstBytes = 0
		for packet in connection:
			if packet[IP].src == dstIP:
				dstBytes += len(str(packet))

		return dstBytes
	elif connection[0].haslayer(IPv6):
		
		dstIP = connection[0][IPv6].dst

		dstBytes = 0
		for packet in connection:
			if packet[IPv6].src == dstIP:
				dstBytes += len(str(packet))

		return dstBytes
	else:
		
		dstIP = connection[0][Ether].dst

		dstBytes = 0
		for packet in connection:
			if packet[Ether].src == dstIP:
				dstBytes += len(str(packet))

		return dstBytes


def getPast2SecondConnections(connection, allConnections):
	if not connection[0].haslayer(IP):
		return []
	
	resList = []
	
	timeWindow = (connection[0].time - 2, connection[0].time)
	connectionIP = (connection[0][IP].src, connection[0][IP].dst)

	for conn in allConnections:
		if not conn[0].haslayer(IP):
			continue

		for packet in conn:
			if packet.time >= timeWindow[0] and packet.time <= connection[0].time\
			and packet[IP].src == (connectionIP[0]) and packet[IP].dst == (connectionIP[1]):
				resList.append(conn)
				break

	return resList
		

def getPast100Connections(connection, allConnections):
	if not connection[0].haslayer(IP):
		return []

	resList = []
	dstIP = connection[0][IP].dst
	startTime = connection[0].time

	for conn in allConnections:
		if not conn[0].haslayer(IP):
			continue

		for packet in conn:

			if conn[0]['IP'].dst == dstIP and conn[0].time <= startTime:
				resList.append(conn)
				break
				

	resList.sort(key=lambda x: x[0].time, reverse=False)
	
	if len(resList) > 100:
		resList = resList[-100:]


	return resList
	


def getSameSrvRate(targetService, past2SecondConnections, result):
	pastCount = 0;

	for conn in past2SecondConnections:
		if getService(conn) == targetService:
			pastCount += 1
			result.append(conn)

	if (len(past2SecondConnections) > 0):
		return float(pastCount/len(past2SecondConnections)) * 100
	else:
		return 0


def getSerrorRate(past2SecondConnections):
	errorCount = 0

	for conn in past2SecondConnections:
		if getTCPFlag(conn) != "SF":
			errorCount += 1

	if (len(past2SecondConnections) > 0):
		return float(errorCount/len(past2SecondConnections)) * 100
	else:
		return 0

def getSrvSerrorRate(same_srv_connections):
	errorCount = 0

	for conn in same_srv_connections:
		if getTCPFlag(conn) != "SF":
			errorCount += 1

	if (len(same_srv_connections) > 0):
		return float(errorCount/len(same_srv_connections)) * 100
	else:
		return 0

	
def getDstHostCount(connection, past100Connections, result):
	if not connection[0].haslayer(IP):
		return 0

	srcIP = connection[0][IP].src
	count = 0
	for conn in past100Connections:
		for packet in conn:
			if conn[0]['IP'].src == srcIP:
				count += 1
				result.append(conn)
				break

	return count


def getDstHostSrvCount(targetService, past100Connections, result):
	
	pastCount = 0;
	for conn in past100Connections:
		if getService(conn) == targetService:
			result.append(conn)
			pastCount += 1

	if (len(past100Connections) > 0):
		return float(pastCount/len(past100Connections)) * 100
	else:
		return 0

def getDstHostSameSrcPortRate(connection, sameIPConnections):
	if not (connection[0].haslayer(TCP) or connection[0].haslayer(UDP)):
		return 0
	srcPort = 0

	if connection[0].haslayer(TCP):
		srcPort = connection[0][TCP].sport
	else:
		srcPort = connection[0][UDP].sport

	
	count = 0
	for conn in sameIPConnections:
		for packet in conn:
			packPort = 0
			if packet.haslayer(TCP):
				packPort = connection[0][TCP].sport
			else:
				packPort = connection[0][UDP].sport

			if packPort == srcPort:
				count += 1
				break

	if (len(sameIPConnections) > 0):
		return float(count/len(sameIPConnections))  * 100
	else:
		return 0



def getDstHostSerrorRate(sameIPConnnections):
	return getSerrorRate(sameIPConnnections)

def getDstHostSrvSerrorRate(sameServiceConnections):
	return getSerrorRate(sameServiceConnections)





def getClassNumber(connection):
	return connection[0].classNum


def getTCPFlag(connection):
	if (not connection[0].haslayer(TCP)):
		return "SF"

	result = "SF"

	connectionAttemptSeen = False
	synAckSeen = False
	connectionMade = False
	connecitonAckSeen = False

	rstSeen = False

	senderIP = ""
	receiverIP = ""

	senderClose = False
	receiverClose = False

	closeSeq = -10

	connectionClosed = False

	for packet in connection:
		flags = packet['TCP'].flags

		sender = packet[IP].src
		receiver = packet[IP].dst

		# Look for SYN
		if (flags & SYN) != 0 and (flags & ACK == 0):
			connectionAttemptSeen = True;
			senderIP = sender
			receiverIP = receiver

		# Look for SYNACK
		if ((flags & SYN) and (flags & ACK)):
			synAckSeen = True

		# Look for ACK
		if (flags & ACK and packet[IP].src == senderIP):
			connectionAckSeen = True
			if synAckSeen:
				connectionMade = True

		if (flags & RST):
			rstSeen = True
			if (not connectionMade):
				if sender == senderIP and (not synAckSeen):
					return "RSTOS0"
				if (not connectionAttemptSeen) and (synAckSeen):
					return "RSTRH"


				return 'REJ'
			else:
				if sender == senderIP:
					return "RST0"
				elif sender == receiverIP:
					return "RSTR"

		if (flags & FIN):
			if connectionAttemptSeen and not synAckSeen:
				return "SH"
			elif synAckSeen and not connectionAttemptSeen:
				return "SHR"	

			if sender == senderIP and (not receiverClose):
				senderClose = True
		#		print packet[TCP].seq
				
			if receiver == receiverIP and (not senderClose):
				receiverClose = True
			closeSeq = packet[TCP].seq

		if (flags & ACK and (senderClose or receiverClose) ):
			if senderClose:
				if sender == receiverIP and packet[TCP].ack == (closeSeq + 1):
					connectionClosed = True
			else:
				if sender == senderIP and packet[TCP].ack == (closeSeq + 1):
					connectionClosed = True


	if (connectionClosed):
		result = "SF"

	if (not (senderClose or receiverClose)):
		result = "S1"


	if (senderClose and (not connectionClosed)):
		result = "S2"

	if (receiverClose and (not connectionClosed)):
		result = "S3"

	if (connectionAttemptSeen and (not synAckSeen)):
		result = "S0"

	if (not connectionAttemptSeen):
		result = "OTH"


	return result

def generateConnectionString(connection, allConnections, setType):
	duration = str(getDuration(connection))
	protocol_type = str(getProtocolType(connection))
	service = str(getService(connection))
	flag = str(getTCPFlag(connection))
	src_bytes = str(getSrcBytes(connection))
	dst_bytes = str(getDstBytes(connection))

	past2SecondConnections = getPast2SecondConnections(connection, allConnections)

	count = str(len(past2SecondConnections))

	same_srv_connections = []
	same_srv_rate = str(getSameSrvRate(service, past2SecondConnections, same_srv_connections))

	serror_rate = str(getSerrorRate(past2SecondConnections))

	srv_serror_rate = str(getSrvSerrorRate(same_srv_connections))

	past100Connections = getPast100Connections(connection, allConnections)

	same_IP_connections = []


	dst_host_count = str(getDstHostCount(connection, past100Connections, same_IP_connections))

	same_srv_100_connections = []

	dst_host_srv_count = str(getDstHostSrvCount(service, past100Connections, same_srv_100_connections))


	dst_host_same_src_port_rate = str(getDstHostSameSrcPortRate(connection, same_IP_connections))
	dst_host_serror_rate = str(getDstHostSerrorRate(same_IP_connections))
	dst_host_srv_serror_rate = str(getDstHostSrvSerrorRate(same_srv_100_connections))

	
	



	classID = str(getClassNumber(connection))



	vector = duration + ',' + protocol_type + ',' + service + ',' + flag + ',' + src_bytes + ',' + \
	dst_bytes + ',' + count + ',' + same_srv_rate + ',' +  serror_rate + ',' +  srv_serror_rate \
	+ ',' + dst_host_count + ',' + dst_host_srv_count + ',' +  dst_host_same_src_port_rate + \
	',' + dst_host_serror_rate + ',' + dst_host_srv_serror_rate + ',' + classID

	if setType == "Kyoto":
		vector += generateKyotoString(connection)

	vector += '\n'

	return vector

def generateKyotoString(connection):
	startTime = connection[0].time
	src_IP = None
	src_port = None
	dst_IP = None
	dst_port = None

	if (connection[0].haslayer(IP)):
		src_IP = connection[0][IP].src
		dst_IP = connection[0][IP].dst

	if (connection[0].haslayer(IPv6)):
		src_IP = connection[0][IPv6].src
		dst_IP = connection[0][IPv6].dst

	if (connection[0].haslayer(TCP)):
		src_port = connection[0][TCP].sport
		dst_port = connection[0][TCP].dport

	if (connection[0].haslayer(UDP)):
		src_port = connection[0][UDP].sport
		dst_port = connection[0][UDP].dport


	vector = ',' + str(startTime) + ',' + str(src_IP) + ',' + str(dst_IP) + ',' + str(src_port) + ',' + str(dst_port)
	return vector

def generateStringsFromConnections(connections, setType):
	csvStrings = []
	for connection in connections:
		csvStrings.append(generateConnectionString(connection, connections, setType))
	return csvStrings



def classifyPackets(packets, clientFilenames):
	classifications = []
	
	for i in range(0, len(packets)):
		classifications.append(0)

	for filename in clientFilenames:
		clientPackets = rdpcap(filename)
		for clientPacket in clientPackets:

			for i in range(0, len(packets)):
				if packets[i] == clientPacket:
					classifications[i] = clientFilenames[filename]

	for i in range(0, len(packets)):
		if classifications[i] == 0:
			payload = str(packets[i].payload)
			classIndex = payload.find("class=")
			if classIndex != -1:
				numIndex = classIndex + 6
				numStr = ""
				while payload[numIndex] in "0123456789":
					numStr += payload[numIndex]
					numIndex += 1

				classifications[i] = int(numStr) 


	return classifications




def removeDuplicates(connections):
	connectionSet = []
	for connection in connections:
		add = True

		for subCon in connectionSet:
			if set(connection) == set(subCon):
				add = False
				break

		if add == True:
			connectionSet.append(connection)

	return connectionSet


def generateKDDFromFiles(filenames, clientFilenames, newFileName, setType):
	fileConnections = []
	for filename in filenames:
		packets = readPCAP(filename)


		classifications = classifyPackets(packets, clientFilenames);

		for i in range(0, len(classifications)):
			packets[i].classNum = classifications[i]
	

		connections = generateData(packets)
		

		fileConnections.append(connections)

	groupConnections = []

	for connections in fileConnections:
		groupConnections.extend(connections)
	
	uniqueConnections = removeDuplicates(groupConnections)

	finalFile = open(newFileName, "w")
	finalFile.close()
	finalFile = open(newFileName, "a")


	headerString = "Duration,Protocol_Type,Service,Connection_State,Src_Bytes,Dst_Bytes,Count,Same_Srv_Rate,\
Serror_rate,srv_serror_rate,dst_host_count,dst_host_srv_count,dst_host_same_src_port_rate,dst_host_serror_rate\
,dst_host_srv_serror_rate,classID"
	
	if setType == "Kyoto":
		headerString += ",Start_Time,Src_IP,Dst_IP,Src_Port,Dst_Port"

	headerString+="\n"

	print "\n *** ...finalising *** \n"

	finalFile.write(headerString)

	for string in generateStringsFromConnections(uniqueConnections, setType):
		finalFile.write(string)



	finalFile.close()





def generate(datafiles, clientfiles, filename, setType):
	print "Generating Dataset"
	print datafiles
	print clientfiles
	generateKDDFromFiles(datafiles, clientfiles, filename, setType)

#test()

def testSeparation(filename):
	packets = readPCAP(filename)
	res = separateNetworkLayer(packets)

	for packet in res['ARP']:
		wrpcap('ARP.pcap', packet, append=True)

	for packet in res['IP']:
		wrpcap('IP.pcap', packet, append=True)


	for packet in res['IPv6']:
		wrpcap('IPv6.pcap', packet, append=True)

	for packet in res['ICMP']:
		wrpcap('ICMP.pcap', packet, append=True)

	for packet in res['other']:
		wrpcap('other.pcap', packet, append=True)


	ARPConnections = separateARPConnection(res['ARP'])
	
	v6Connections = separateIPv6Connection(res['IPv6'])



#generate(['h3.pcap'], {'ch2_6769.pcap': 20, 'ch2_8299.pcap': 10, 'ch3_6168.pcap':25, 'ch1_5673.pcap': 15, 'ch1_8631.pcap':10}, 'Beno.csv', 'Kyoto')