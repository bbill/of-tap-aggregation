#!/usr/bin/python
""" Running Mininet with custom topology to test OpenFlow TAP Aggregation App

Theree directly connected switches plus three hosts:

   h1 ---\
         s1 --- s2 --- s3 --- h3
   h2 ---/

Usage: sudo ./topo.py <controller_ip>
"""

import sys
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo

def int2dpid( dpid ):
   try:
      dpid = hex( dpid )[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid
   except IndexError:
      raise Exception( 'Unable to derive default datapath ID - '
                       'please either specify a dpid or use a '
		       'canonical switch name such as s23.' )

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self):
        "Create custom topo."
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost( 'h1', ip='10.0.0.1' )
        h2 = self.addHost( 'h2', ip='10.0.0.2' )
        h3 = self.addHost( 'h3', ip='10.0.0.3' )
        s1 = self.addSwitch( 's1', dpid=int2dpid(1), protocols='OpenFlow13' )
        s2 = self.addSwitch( 's2', dpid=int2dpid(2), protocols='OpenFlow13' )
        s3 = self.addSwitch( 's3', dpid=int2dpid(3), protocols='OpenFlow13' )

        # Add links
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        self.addLink( s3, h3 )

if __name__ == "__main__":
    setLogLevel( 'info' )
    info( '*** Creating topo\n')
    net = Mininet( topo=MyTopo(), build=False )
    ip = '127.0.0.1'
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    info( '*** Configuring remote controller ({})\n'.format(ip))
    c0 = RemoteController('c0', ip=ip, port=6633)
    net.addController(c0)
    info( '*** Starting network\n')
    net.build()
    net.start()
    info( '*** Running CLI\n' )
    CLI(net)
    info( '*** Stopping network' )
    net.stop()
