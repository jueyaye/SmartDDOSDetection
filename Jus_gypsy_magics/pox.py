
"""
a script to call the POX controller within mininet without the need to run a remote controller.
"""

from mininet.node import Controller
from os import environ

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

POXDIR = environ[ 'HOME' ] + '/pox'

class POX( Controller ):
	
    #need to include the ability to set the default POX rules
    config = ConfigParser();
    config.read('controllerConfig.ini');
    
    assert config.get("POX", "rules")

    def __init__( self, name, cdir=POXDIR,
                  command = 'python pox.py',
                  cargs = config.get("POX", "rules"),
                  **kwargs ):
        Controller.__init__( self, name, cdir=cdir,
                             command=command,
                             cargs=cargs, **kwargs )

controllers={ 'pox': POX }