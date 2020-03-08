from mininet.node import Controller
from os import environ

ONOSDIR = environ[ 'HOME' ] + '/onos'

class CustomCntrl( Controller ):
    def __init__( self, name, cdir=ONOSDIR,
                  command='python onos.py',
                  cargs=( 'openflow.of_01 --port=%s '
                          'forwarding.l2_learning' ),
                  **kwargs ):
        Controller.__init__( self, name, cdir=cdir,
                             command=command,
                             cargs=cargs, **kwargs )