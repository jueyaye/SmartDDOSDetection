#!/usr/bin/python

"""
an abridged version of the deafult onos.py from ~/onos/tools/dev/mininet

allows for the creation of a controller within mininet without the need the for a remote controller.

"""

from mininet.node import Controller, OVSSwitch, UserSwitch
from mininet.nodelib import LinuxBridge
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo, Topo
from mininet.log import setLogLevel, info, warn, error, debug
from mininet.cli import CLI
from mininet.util import quietRun, specialClass
from mininet.examples.controlnet import MininetFacade

from os import environ
from os.path import dirname, join, isfile
from sys import argv
from glob import glob
import time
from functools import partial

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

### ONOS Environment

KarafPort = 8101	# ssh port indicating karaf is running
GUIPort = 8181		# GUI/REST port
OpenFlowPort = 6653 	# OpenFlow port
CopycatPort = 9876      # Copycat port

def defaultUser():
    "Return a reasonable default user"
    if 'SUDO_USER' in environ:
        return environ[ 'SUDO_USER' ]
    try:
        user = quietRun( 'who am i' ).split()[ 0 ]
    except:
        user = 'nobody'
    return user

# Module vars, initialized below
HOME = ONOS_ROOT = ONOS_USER = None

# --updated-- to include the rules specified in the controller config
ONOS_APPS = ONOS_WEB_USER = ONOS_WEB_PASS = ONOS_TAR = None

def initONOSEnv():
    """Initialize ONOS environment (and module) variables
       This is ugly and painful, but they have to be set correctly
       in order for the onos-setup-karaf script to work.
       nodes: list of ONOS nodes
       returns: ONOS environment variable dict"""
    # pylint: disable=global-statement
    global HOME, ONOS_ROOT, ONOS_USER
    global ONOS_APPS, ONOS_WEB_USER, ONOS_WEB_PASS
    env = {}
    
    def sd( var, val ):
        "Set default value for environment variable"
        env[ var ] = environ.setdefault( var, val )
        return env[ var ]

    assert environ[ 'HOME' ]

    HOME = sd( 'HOME', environ[ 'HOME' ] )
    ONOS_ROOT = sd( 'ONOS_ROOT',  join( HOME, 'onos' ) )
    environ[ 'ONOS_USER' ] = defaultUser()
    ONOS_USER = sd( 'ONOS_USER', defaultUser() )

    # Set to items passed in the "controllerConfig.ini"
    config = ConfigParser();
    config.read('controllerConfig.ini');

    assert config.get("ONOS", "rules")
    ONOS_APPS = sd( 'ONOS_APPS',
                     config.get("ONOS", "rules"))

    # ONOS_WEB_{USER,PASS} isn't respected by onos-karaf:
    environ.update( ONOS_WEB_USER='karaf', ONOS_WEB_PASS='karaf' )
    ONOS_WEB_USER = sd( 'ONOS_WEB_USER', 'karaf' )
    ONOS_WEB_PASS = sd( 'ONOS_WEB_PASS', 'karaf' )
    return env


def updateNodeIPs( env, nodes ):
    "Update env dict and environ with node IPs"
    # Get rid of stale junk
    for var in 'ONOS_NIC', 'ONOS_CELL', 'ONOS_INSTANCES':
        env[ var ] = ''
    for var in environ.keys():
        if var.startswith( 'OC' ):
            env[ var ] = ''
    for index, node in enumerate( nodes, 1 ):
        var = 'OC%d' % index
        env[ var ] = node.IP()
    if nodes:
        env[ 'OCI' ] = env[ 'OCN' ] = env[ 'OC1' ]
    env[ 'ONOS_INSTANCES' ] = '\n'.join(
        node.IP() for node in nodes )
    environ.update( env )
    return env


tarDefaultPath = 'buck-out/gen/tools/package/onos-package/onos.tar.gz'

def unpackONOS( destDir='/tmp', run=quietRun ):
    "Unpack ONOS and return its location"
    global ONOS_TAR
    environ.setdefault( 'ONOS_TAR', join( ONOS_ROOT, tarDefaultPath ) )
    ONOS_TAR = environ[ 'ONOS_TAR' ]
    tarPath = ONOS_TAR
    if not isfile( tarPath ):
        raise Exception( 'Missing ONOS tarball %s - run buck build onos?'
                         % tarPath )
    info( '(unpacking %s)' % destDir)
    success = '*** SUCCESS ***'
    cmds = ( 'mkdir -p "%s" && cd "%s" && tar xzf "%s" && echo "%s"'
             % ( destDir, destDir, tarPath, success ) )
    result = run( cmds, shell=True, verbose=True )
    if success not in result:
        raise Exception( 'Failed to unpack ONOS archive %s in %s:\n%s\n' %
                         ( tarPath, destDir, result ) )
    # We can use quietRun for this usually
    tarOutput = quietRun( 'tar tzf "%s" | head -1' % tarPath, shell=True)
    tarOutput = tarOutput.split()[ 0 ].strip()
    assert '/' in tarOutput
    onosDir = join( destDir, dirname( tarOutput ) )
    # Add symlink to log file
    run( 'cd %s; ln -s onos*/apache* karaf;'
         'ln -s karaf/data/log/karaf.log log' % destDir,
         shell=True )
    return onosDir


def waitListening( server, port=80, callback=None, sleepSecs=.5,
                   proc='java' ):
    "Simplified netstat version of waitListening"
    while True:
        lines = server.cmd( 'netstat -natp' ).strip().split( '\n' )
        entries = [ line.split() for line in lines ]
        portstr = ':%s' % port
        listening = [ entry for entry in entries
                      if len( entry ) > 6 and portstr in entry[ 3 ]
                      and proc in entry[ 6 ] ]
        if listening:
            break
        info( '.' )
        if callback:
            callback()
        time.sleep( sleepSecs )


### Mininet classes

def RenamedTopo( topo, *args, **kwargs ):
    """Return specialized topo with renamed hosts
       topo: topo class/class name to specialize
       args, kwargs: topo args
       sold: old switch name prefix (default 's')
       snew: new switch name prefix
       hold: old host name prefix (default 'h')
       hnew: new host name prefix
       This may be used from the mn command, e.g.
       mn --topo renamed,single,spref=sw,hpref=host"""
    sold = kwargs.pop( 'sold', 's' )
    hold = kwargs.pop( 'hold', 'h' )
    snew = kwargs.pop( 'snew', 'cs' )
    hnew = kwargs.pop( 'hnew' ,'ch' )
    topos = {}  # TODO: use global TOPOS dict
    if isinstance( topo, str ):
        # Look up in topo directory - this allows us to
        # use RenamedTopo from the command line!
        if topo in topos:
            topo = topos.get( topo )
        else:
            raise Exception( 'Unknown topo name: %s' % topo )
    # pylint: disable=no-init
    class RenamedTopoCls( topo ):
        "Topo subclass with renamed nodes"
        def addNode( self, name, *args, **kwargs ):
            "Add a node, renaming if necessary"
            if name.startswith( sold ):
                name = snew + name[ len( sold ): ]
            elif name.startswith( hold ):
                name = hnew + name[ len( hold ): ]
            return topo.addNode( self, name, *args, **kwargs )
    return RenamedTopoCls( *args, **kwargs )


# We accept objects that "claim" to be a particular class,
# since the class definitions can be both execed (--custom) and
# imported (in another custom file), which breaks isinstance().
# In order for this to work properly, a class should not be
# renamed so as to inappropriately omit or include the class
# name text. Note that mininet.util.specialClass renames classes
# by adding the specialized parameter names and values.

def isONOSNode( obj ):
    "Does obj claim to be some kind of ONOSNode?"
    return ( isinstance( obj, ONOSNode) or
             'ONOSNode' in type( obj ).__name__ )

def isONOSCluster( obj ):
    "Does obj claim to be some kind of ONOSCluster?"
    return ( isinstance( obj, ONOSCluster ) or
             'ONOSCluster' in type( obj ).__name__ )


class ONOSNode( Controller ):
    "ONOS cluster node"

    def __init__( self, name, **kwargs ):
        "alertAction: exception|ignore|warn|exit (exception)"
        kwargs.update( inNamespace=True )
        self.alertAction = kwargs.pop( 'alertAction', 'exception' )
        Controller.__init__( self, name, **kwargs )
        self.dir = '/tmp/%s' % self.name
        self.client = self.dir + '/karaf/bin/client'
        self.ONOS_HOME = '/tmp'
        self.cmd( 'rm -rf', self.dir )
        self.ONOS_HOME = unpackONOS( self.dir, run=self.ucmd )
        self.ONOS_ROOT = ONOS_ROOT

    # pylint: disable=arguments-differ

    def start( self, env, nodes=() ):
        """Start ONOS on node
           env: environment var dict
           nodes: all nodes in cluster"""
        env = dict( env )
        env.update( ONOS_HOME=self.ONOS_HOME )
        self.updateEnv( env )
        karafbin = glob( '%s/apache*/bin' % self.ONOS_HOME )[ 0 ]
        onosbin = join( ONOS_ROOT, 'tools/test/bin' )
        self.cmd( 'export PATH=%s:%s:$PATH' % ( onosbin, karafbin ) )
        self.cmd( 'cd', self.ONOS_HOME )
        self.ucmd( 'mkdir -p config && '
                   'onos-gen-partitions config/cluster.json',
                   ' '.join( node.IP() for node in nodes ) )
        info( '(starting %s)' % self )
        service = join( self.ONOS_HOME, 'bin/onos-service' )
        self.ucmd( service, 'server 1>../onos.log 2>../onos.log'
                   ' & echo $! > onos.pid; ln -s `pwd`/onos.pid ..' )
        self.onosPid = int( self.cmd( 'cat onos.pid' ).strip() )
        self.warningCount = 0

    # pylint: enable=arguments-differ

    def intfsDown( self ):
        """Bring all interfaces down"""
        for intf in self.intfs.values():
            cmdOutput = intf.ifconfig( 'down' )
            # no output indicates success
            if cmdOutput:
                error( "Error setting %s down: %s " % ( intf.name, cmdOutput ) )

    def intfsUp( self ):
        """Bring all interfaces up"""
        for intf in self.intfs.values():
            cmdOutput = intf.ifconfig( 'up' )
            if cmdOutput:
                error( "Error setting %s up: %s " % ( intf.name, cmdOutput ) )

    def stop( self ):
        # XXX This will kill all karafs - too bad!
        self.cmd( 'pkill -HUP -f karaf.jar && wait' )
        self.cmd( 'rm -rf', self.dir )

    def sanityAlert( self, *args ):
        "Alert to raise on sanityCheck failure"
        info( '\n' )
        if self.alertAction == 'exception':
            raise Exception( *args )
        if self.alertAction == 'warn':
            warn( *args + ( '\n', ) )
        elif self.alertAction == 'exit':
            error( '***',  *args +
                   ( '\nExiting. Run "sudo mn -c" to clean up.\n', ) )
            exit( 1 )

    def isRunning( self ):
        "Is our ONOS process still running?"
        cmd = ( 'ps -p %d  >/dev/null 2>&1 && echo "running" ||'
                'echo "not running"' )
        return self.cmd( cmd % self.onosPid ).strip() == 'running'

    def checkLog( self ):
        "Return log file errors and warnings"
        log = join( self.dir, 'log' )
        errors, warnings = [], []
        if isfile( log ):
            lines = open( log ).read().split( '\n' )
            errors = [ line for line in lines if 'ERROR' in line ]
            warnings = [ line for line in lines if 'WARN'in line ]
        return errors, warnings

    def memAvailable( self ):
        "Return available memory in KB (or -1 if we can't tell)"
        lines = open( '/proc/meminfo' ).read().strip().split( '\n' )
        entries = map( str.split, lines )
        index = { entry[ 0 ]: entry for entry in entries }
        # Check MemAvailable if present
        default = ( None, '-1', 'kB' )
        _name, count, unit = index.get( 'MemAvailable:', default )
        if unit.lower() == 'kb':
            return int( count )
        return -1

    def sanityCheck( self, lowMem=100000 ):
        """Check whether we've quit or are running out of memory
           lowMem: low memory threshold in KB (100000)"""
        # Are we still running?
        if not self.isRunning():
            self.sanityAlert( 'ONOS node %s has died' % self.name )
        # Are there errors in the log file?
        errors, warnings  = self.checkLog()
        if errors:
            self.sanityAlert( 'ONOS startup errors:\n<<%s>>' %
                              '\n'.join( errors ) )
        warningCount = len( warnings )
        if warnings and warningCount > self.warningCount:
            warn( '(%d warnings)' % len( warnings ) )
            self.warningCount = warningCount
        # Are we running out of memory?
        mem = self.memAvailable()
        if mem > 0 and mem < lowMem:
            self.sanityAlert( 'Running out of memory (only %d KB available)'
                              % mem )

    def waitStarted( self ):
        "Wait until we've really started"
        info( '(checking: karaf' )
        while True:
            status = self.ucmd( 'karaf status' ).lower()
            if 'running' in status and 'not running' not in status:
                break
            info( '.' )
            self.sanityCheck()
            time.sleep( 1 )
        info( ' ssh-port' )
        waitListening( server=self, port=KarafPort, callback=self.sanityCheck )
        info( ' openflow-port' )
        waitListening( server=self, port=OpenFlowPort,
                       callback=self.sanityCheck )
        info( ' client' )
        while True:
            result = quietRun( '%s -h %s "apps -a"' %
                               ( self.client, self.IP() ), shell=True )
            if 'openflow' in result:
                break
            info( '.' )
            self.sanityCheck()
            time.sleep( 1 )
        info( ' node-status' )
        while True:
            result = quietRun( '%s -h %s "nodes"' %
                               ( self.client, self.IP() ), shell=True )
            nodeStr = 'id=%s, address=%s:%s, state=READY, updated' %\
                      ( self.IP(), self.IP(), CopycatPort )
            if nodeStr in result:
                break
            info( '.' )
            self.sanityCheck()
            time.sleep( 1 )
        info( ')\n' )

    def updateEnv( self, envDict ):
        "Update environment variables"
        cmd = ';'.join( ( 'export %s="%s"' % ( var, val )
                          if val else 'unset %s' % var )
                        for var, val in envDict.iteritems() )
        self.cmd( cmd )

    def ucmd( self, *args, **_kwargs ):
        "Run command as $ONOS_USER using sudo -E -u"
        if ONOS_USER != 'root':  # don't bother with sudo
            args = [ "sudo -E -u $ONOS_USER PATH=$PATH "
                     "bash -c '%s'" % ' '.join( args ) ]
        return self.cmd( *args )


class ONOSCluster( Controller ):
    "ONOS Cluster"
    # Offset for port forwarding
    portOffset = 0
    def __init__( self, *args, **kwargs ):
        """name: (first parameter)
           *args: topology class parameters
           ipBase: IP range for ONOS nodes
           forward: default port forwarding list
           portOffset: offset to port base (optional)
           topo: topology class or instance
           nodeOpts: ONOSNode options
           **kwargs: additional topology parameters
        By default, multiple ONOSClusters will increment
        the portOffset automatically; alternately, it can
        be specified explicitly.
        """

        args = list( args )
        name = args.pop( 0 )
        topo = kwargs.pop( 'topo', None )
        self.nat = kwargs.pop( 'nat', 'nat0' )
        nodeOpts = kwargs.pop( 'nodeOpts', {} )
        self.portOffset = kwargs.pop( 'portOffset', ONOSCluster.portOffset )

        # Pass in kwargs to the ONOSNodes instead of the cluster
        "alertAction: exception|ignore|warn|exit (exception)"
        alertAction = kwargs.pop( 'alertAction', None )
        if alertAction:
            nodeOpts[ 'alertAction'] = alertAction

        # Default: single switch with 1 ONOS node
        if not topo:
            topo = SingleSwitchTopo
            if not args:
                args = ( 1, )
        if not isinstance( topo, Topo ):
            topo = RenamedTopo( topo, *args, hnew='onos', **kwargs )

        self.ipBase = kwargs.pop( 'ipBase', '192.168.123.0/24' )
        self.forward = kwargs.pop( 'forward',
                                   [ KarafPort, GUIPort, OpenFlowPort ] )

        super( ONOSCluster, self ).__init__( name, inNamespace=False )
        fixIPTables()
        
        self.env = initONOSEnv()
        self.net = Mininet( topo=topo, ipBase=self.ipBase,
                            host=partial( ONOSNode, **nodeOpts ),
                            switch=LinuxBridge,
                            controller=None )

        if self.nat:
            self.net.addNAT( self.nat ).configDefault()
            
        updateNodeIPs( self.env, self.nodes() )
        self._remoteControllers = []
        # Update port offset for more ONOS clusters
        ONOSCluster.portOffset += len( self.nodes() )

    def start( self ):
        "Start up ONOS cluster"
        info( '*** ONOS_APPS = %s\n' % ONOS_APPS )
        self.net.start()
        for node in self.nodes():
            node.start( self.env, self.nodes() )
        info( '\n' )
        self.configPortForwarding( ports=self.forward, action='A' )
        self.waitStarted()
        return

    def waitStarted( self ):
        "Wait until all nodes have started"
        startTime = time.time()
        for node in self.nodes():
            info( node )
            node.waitStarted()
        info( '*** Waited %.2f seconds for ONOS startup' %
              ( time.time() - startTime ) )

    def stop( self ):
        "Shut down ONOS cluster"
        self.configPortForwarding( ports=self.forward, action='D' )
        for node in self.nodes():
            node.stop()
        self.net.stop()

    def nodes( self ):
        "Return list of ONOS nodes"
        return [ h for h in self.net.hosts if isONOSNode( h ) ]

    def configPortForwarding( self, ports=[], action='A' ):
        """Start or stop port forwarding (any intf) for all nodes
           ports: list of ports to forward
           action: A=add/start, D=delete/stop (default: A)"""
        self.cmd( 'iptables -' + action, 'FORWARD -d', self.ipBase,
                  '-j ACCEPT' )
        for port in ports:
            for index, node in enumerate( self.nodes() ):
                ip, inport = node.IP(), port + self.portOffset + index
                # Configure a destination NAT rule
                self.cmd( 'iptables -t nat -' + action,
                          'PREROUTING -t nat -p tcp --dport', inport,
                          '-j DNAT --to-destination %s:%s' % ( ip, port ) )


class ONOSSwitchMixin( object ):
    "Mixin for switches that connect to an ONOSCluster"
    def start( self, controllers ):
        "Connect to ONOSCluster"
        self.controllers = controllers
        assert ( len( controllers ) is 1 and
                 isONOSCluster( controllers[ 0 ] ) )
        clist = controllers[ 0 ].nodes()
        return super( ONOSSwitchMixin, self ).start( clist )

class ONOSOVSSwitch( ONOSSwitchMixin, OVSSwitch ):
    "OVSSwitch that can connect to an ONOSCluster"
    pass

class ONOSUserSwitch( ONOSSwitchMixin, UserSwitch):
    "UserSwitch that can connect to an ONOSCluster"
    pass


### Ugly utility routines
def fixIPTables():
    "Fix LinuxBridge warning"
    for s in 'arp', 'ip', 'ip6':
        quietRun( 'sysctl net.bridge.bridge-nf-call-%stables=0' % s )


### Test code
def test( serverCount ):
    "Test this setup"
    setLogLevel( 'info' )
    net = Mininet( topo=SingleSwitchTopo( 3 ),
                   controller=[ ONOSCluster( 'c0', serverCount ) ],
                   switch=ONOSOVSSwitch )
    net.start()
    net.waitConnected()
    CLI( net )
    net.stop()

# For interactive use, exit on error
exitOnError = dict( nodeOpts={ 'alertAction': 'exit' } )
ONOS = specialClass( ONOSCluster, defaults=exitOnError )

### Exports for bin/mn
controllers = { 'onos': ONOS,
                'default': ONOS }

# XXX Hack to change default controller as above doesn't work
findController = lambda: controllers[ 'default' ]

switches = { 'onos': ONOSOVSSwitch,
             'onosovs': ONOSOVSSwitch,
             'onosuser': ONOSUserSwitch,
             'default': ONOSOVSSwitch }

# Null topology so we can control an external/hardware network
topos = { 'none': Topo }