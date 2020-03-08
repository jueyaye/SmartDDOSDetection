# User manual:

Running the Matos dataset generator…

## Prerequisites:

scapy:

https://github.com/secdev/scapy/releases

hping3:

 https://github.com/antirez/hping

mininet:

 https://github.com/mininet/mininet

## Configurable (example files are provided with the same name):

To set custom controllers (currently only ONOS and POX):

1. Open the controllerConfig.ini
2. List the controller type you want to use
3. Under the controller type specify the rules that you want to controller to run on start
4. Repeat steps 2 and 3 for each separate controller you want to implement

To set example behavior:

1. Open the exampleBehaviour.ini
2. List the behavior you want to emulate
3. Under the behavior list the following:
  1. Number of clients in the behavior
  2. The script to run on each clients
  3. The name of the clients in the behavior
  4. Number of servers in the behavior
  5. The script to run on each server
  6. The name of the servers in the behavior
  7. You can optionally at this point set the preferred port for the servers within the network
  8. Next set the duration of the run
  9. The start delay
  10. The total number of times the behavior is to be run
  11. And the downtime between each run
  12. Finally set the traffic class, used to classify the behavior in the dataset produced
 
## Running the topology builder/network dataset generator:

After obtaining the prerequisite software&#39;s and defining a suitable configuration in both config files. In the directory that the project is located in. The topology builder can be run through:

 sudo ./miniedit.py

miniedit will launch and you will be able to specify the topology that you want to implement. There is also the option to load a previous topology (\*topologies must be loaded in as a .mn file).

Once ready the simulation can then be launched from within miniedit by selecting the run icon located at the lower left-hand corner of the gui. As a disclaimer, the available error parsing/handling is minimum at best and earnest is place on the user to match to the behavior&#39;s config files to the network topologies. If there is a discrepancy between the config files and the network topology and the application crashes simply correct the discrepancy and restart the application.

The simulation will run through the specified behaviors and generate the relevant datasets. Produced datasets can be found in the logs file which the application will produce if not currently available. Note, for large networks the simulation and dataset generation can take some time to complete.