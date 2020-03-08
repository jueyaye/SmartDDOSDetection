
from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from mininet.topo import Topo
from mininet.link import *

from random import randint

import subprocess
import os
import errno

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

# Clean mininet if the program is stopped early
def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    subprocess.Popen("sudo mn -c".split())
    sys.exit(0)


def cleanUpProcesses(net):
	for h in net.hosts:
		pid =  net.get(h.name).cmd('echo $!')
		h.cmd('kill ' + pid)
		print pid

	for h in net.hosts:
		pid =  net.get(h.name).cmd('echo $!')
	#	h.cmd('kill SIGTERM ' + pid)
		print pid


def runTCPDump(net, filenames):
	for h in net.hosts:
		dumpCommand = "sudo tcpdump -i " + h.name + "-eth0 -w ./logs/" + h.name + ".pcap &"
		h.cmd(dumpCommand)
		filenames.append("./logs/" + h.name + ".pcap")
		print dumpCommand

def runHosts(net, clientFilenames, runtime):

	hosts = net.hosts

	usedPorts = {}
	for h in net.hosts:
		usedPorts[h.name] = []

	hostsConfig = ConfigParser();

	hostsConfig.read('host_behaviour.ini')
	
	# Loop through the modules
	for section in hostsConfig.sections():
		print "Running " + str(section)

		moduleTargets = []

		config = moduleConfig(hostsConfig, section)

		
		if config.serverHosts != None:
			launchServerWithHosts(net, config, usedPorts, moduleTargets)
		else:
			print "YEAH BOYS"

		if config.clientHosts != None:
			launchClientWithHosts(net, config, usedPorts, moduleTargets, clientFilenames)

		runtime = max(runtime, config.startDelay + (config.runtime + config.downtime) * config.totalRuns)

def launchClientWithHosts(net, config, usedPorts, moduleTargets, clientFilenames):
	portIndex = 0

	for host in config.clientHosts:

		netHost = net.get(host)

		for target in moduleTargets:
		
			selfPort = selectNewPort(netHost, usedPorts, None, [])

			dumpCommand = "sudo tcpdump -i " + netHost.name + "-eth0 port " + str(selfPort) +\
			 " -w ./logs/c" + netHost.name + "_" + str(selfPort) + ".pcap &"
	


			cmdStr = "./hostScript.sh " + config.clientScript + " " + str(config.startDelay) +\
			 " " + str(config.totalRuns) + " " + \
			str(config.downtime) + " " + str(netHost.IP()) + " " + str(selfPort) + " " + target[1] + " " \
			+ str(target[0]) + " " + str(config.trafficClass) + " " + str(config.runtime) + " &"
			
			netHost.cmd(cmdStr)

			netHost.cmd(dumpCommand)

			clientFilenames[("./logs/c" + netHost.name + "_" + str(selfPort) + ".pcap")] = config.trafficClass
			print dumpCommand
			print cmdStr

def launchServerWithHosts(net, config, usedPorts, moduleTargets):
	for host in config.serverHosts:
	
		netHost = net.get(host)

		port = selectNewPort(netHost, usedPorts, config.preferredPort, moduleTargets)


		if config.serverScript != None:
			command = genHostCommand(config, port, netHost)

			netHost.cmd(command)
			print command


def selectNewPort(host, usedPorts, prefPort, moduleTargets):
	if (prefPort == None):
		preferredPort = randint(5000, 10000)
	else:
		preferredPort = prefPort

	port = 0

	if preferredPort not in usedPorts[host.name]:
		port = preferredPort
	else:
		if len(usedPorts) > 0:
			port = (usedPorts[host.name])[len(usedPorts[host.name]) - 1] + 1
		else:
			port = preferredPort

	usedPorts[host.name].append(port)
	moduleTargets.append((port, host.IP()))

	return port

def genHostCommand(config, port, host):
	cmdStr = "./hostScript.sh " + config.serverScript + " " + str(config.startDelay) + " " +\
	 str(config.totalRuns) + " " + str(config.downtime) + " " + host.IP() + " " + str(port) + " " \
	 + "0 " + "0 " + str(config.trafficClass) + " " + str(config.runtime) + " &"
	return cmdStr


class moduleConfig():
	def __init__(self, hostsConfig, section):
		self.clients = None
		self.clientScript = None
		self.clientHosts = None
		self.servers = None
		self.serverScript = None
		self.serverHosts = None
		self.runtime = 0
		self.downtime = 0
		self.startDelay = 0
		self.totalRuns = 1
		self.preferredPort = None
		self.trafficClass = None

		if hostsConfig.has_option(section, "clients"):
			self.clients = int(hostsConfig.get(section, "clients"))
			self.clientScript = (hostsConfig.get(section, "client-script"))
			if hostsConfig.has_option(section, "client-hosts"):
				self.clientHosts = (hostsConfig.get(section, "client-hosts")).split(',')

		if hostsConfig.has_option(section, "servers"):
			self.servers = int(hostsConfig.get(section, "servers"))
			if hostsConfig.has_option(section, "server-script"):
				self.serverScript = (hostsConfig.get(section, "server-script"))
			if hostsConfig.has_option(section, "server-hosts"):
				self.serverHosts = (hostsConfig.get(section, "server-hosts")).split(',')
			if hostsConfig.has_option(section, "preferred-server-port"):
				self.preferredPort = int(hostsConfig.get(section, "preferred-server-port"))

		if hostsConfig.has_option(section, "runtime"):
			self.runtime = int(hostsConfig.get(section, "runtime"))

		if hostsConfig.has_option(section, "start-delay"):
			self.startDelay = int(hostsConfig.get(section, "start-delay"))

		if hostsConfig.has_option(section, "total-runs"):
			self.totalRuns = int(hostsConfig.get(section, "total-runs"))

		if hostsConfig.has_option(section, "downtime"):
			self.downtime = int(hostsConfig.get(section, "downtime"))

		if hostsConfig.has_option(section, "traffic-class"):
			self.trafficClass = (hostsConfig.get(section, "traffic-class"))

