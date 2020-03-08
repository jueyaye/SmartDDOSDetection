# Smart DDOS Detection

A modular network simulator for producing datasets to train "smart" Intrusion Detection Systems (IDSs). This project aims to overcome the existing issue of poor availability of large, realistic datasets that include a range of typical benign traffic as well as malicious attacks to train IDSs. This project aimed to create a modular, intention-based interface for network administrators to simulate a network and produce a relevant and realistic dataset for use in a machine learning based IDS.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them

scapy (used to read the pcap files generated from tcpdump)

```
https://github.com/secdev/scapy/releases
```

hping3 (attack simulation tool)

```
https://github.com/antirez/hping
```

mininet (network simulator)

```
https://github.com/mininet/mininet
```

### Configuration

To set custom controllers (currently only ONOS and POX):

- Open the controllerConfig.ini
- List the controller type you want to use
- Under the controller type specify the rules that you want to controller to run on start
- Repeat steps 2 and 3 for each separate controller you want to implement

To set example behavior:

- Open the exampleBehaviour.ini
- List the behavior you want to emulate
- Under the behavior list the following:
  - Number of clients in the behavior
  - The script to run on each clients
  - The name of the clients in the behavior
  - Number of servers in the behavior
  - The script to run on each server
  - The name of the servers in the behavior
  - You can optionally at this point set the preferred port for the servers within the network
  - Next set the duration of the run
  - The start delay
  - The total number of times the behavior is to be run
  - And the downtime between each run
  - Finally set the traffic class, used to classify the behavior in the dataset produced

#### Example controllerConfig.ini

```
[ONOS]
rules: drivers,openflow,fwd,proxyarp,mobility

[POX]
rules: openflow.of_01 --port=%s forwarding.l2_learning
```

#### Example hostBehaviour.ini

```
[general]
runtime: 80


[mod1]
clients: 1
client-script: HTTPClient.py
client-hosts: h1,h2,h3
servers: 1
server-script: HTTPServer.py
server-hosts: h4
preferred-server-port: 80

runtime: 2
start-delay: 2
total-runs: 3
downtime: 5

traffic-class: 10

[mod2]
clients : 1
client-script: ICMPSmurfFlood.py
client-hosts: h1

servers: 1
server-hosts: h2

traffic-class: 15

runtime: 1
start-delay: 10
total-runs: 2
downtime: 15


[mod3]
clients: 1
client-script: SYNFlood.py
client-hosts: h5

servers: 1
server-hosts: h3

traffic-class: 20

runtime: 1
start-delay: 5
total-runs: 1
downtime: 3


[mod4]
clients: 1
client-script: UDPDNSFlood.py
client-hosts: h6

servers: 1
server-hosts: h4

traffic-class: 25

runtime: 3
start-delay: 30
total-runs: 1
downtime: 2

```

## Running the topology builder/network dataset generator

After obtaining the prerequisite software’s and defining a suitable configuration in both config files. In the directory that the project is located in. The topology builder can be run through:

```
sudo ./miniedit.py
```

miniedit will launch and you will be able to specify the topology that you want to implement. There is also the option to load a previous topology (\*topologies must be loaded in as a .mn file).

Once ready the simulation can then be launched from within miniedit by selecting the run icon located at the lower left-hand corner of the gui. As a disclaimer, the available error parsing/handling is minimum at best and earnest is place on the user to match to the behavior’s config files to the network topologies. If there is a discrepancy between the config files and the network topology and the application crashes simply correct the discrepancy and restart the application.

The simulation will run through the specified behaviors and generate the relevant datasets. Produced datasets can be found in the logs file which the application will produce if not currently available. Note, for large networks the simulation and dataset generation can take some time to complete.

![Example miniedit running](https://github.com/jueyaye/SmartDDOSDetection/demo.png)
