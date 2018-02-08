#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import os
import time
import subprocess
import signal

import numpy as np
import mininet.topo
import mininet.net
import mininet.node
import mininet.cli

class LinuxRouter( mininet.node.Node ):

    # Habilitando encaminhamento IP

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.upv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class Topo(mininet.topo.Topo):

    '''
        Configurando a rede:
        Host alice
        Host bob
        Host Mallory (atacante)
    '''

    def build( self ):

        # Criando os Nodes

        alice= self.addHost('alice', cls= mininet.node.Host, ip= '192.1.1.2/24', defaulRouter= None )
        bob= self.addHost('bob', cls= mininet.node.Host, ip= '172.1.1.2/24', defaultRouter= None )
        mallory= self.addHost('mallory', cls= mininet.node.Host, ip= '191.1.1.2/24', defaultRouter= None )

        # Criando os roteadores

        r1_alice= self.addNode( 'r1_alice', cls= LinuxRouter )
        r2_alice= self.addNode( 'r2_alice', cls= LinuxRouter )

        r3_bob= self.addNode( 'r3_bob', cls= LinuxRouter )
        r4_bob= self.addNode( 'r4_bob', cls= LinuxRouter )

        rb_alice= self.addNode( 'rb_alice', cls= LinuxRouter)
        rb_bob= self.addNode( 'rb_bob', cls= LinuxRouter)

        #Configurado links

        borda= dict( bw= 100, delay= '1ms', max_queue_size= 10 )
        nucleo= dict( bw= 1.5, delay= '20ms', max_queue_size= 1000 )
        bneck= dict( bw= 1.5, delay= '20ms', max_queue_size= 1000 ) #0.5, 20ms, 1000

        # Adicionando links Alice

        self.addLink( alice, r1_alice, cls= mininet.link.TCLink, **borda )  #eth0 -> eth0
        self.addLink( alice, r2_alice, cls= mininet.link.TCLink, **borda )  #eth1 -> eth0

        # Adicionando links Bob

        self.addLink( bob, r3_bob, cls= mininet.link.TCLink, **borda )  #eth0 -> eth0-
        self.addLink( bob, r4_bob, cls= mininet.link.TCLink, **borda )  #eth1 -> eth0

        # Adicionando links routers to routers

        self.addLink( r1_alice, rb_alice, cls= mininet.link.TCLink, **nucleo )  #eth2 -> eth0
        self.addLink( r2_alice, rb_alice, cls= mininet.link.TCLink, **nucleo )  #eth1 -> eth1

        self.addLink( r3_bob, rb_bob, cls= mininet.link.TCLink, **nucleo )  #eth1 -> eth0
        self.addLink( r4_bob, rb_bob, cls= mininet.link.TCLink, **nucleo )  #eth1 -> eth1

        #Adicionando links bottleneck

        self.addLink( rb_alice, rb_bob, cls= mininet.link.TCLink, **bneck )  #eth2 -> #eth2

        # Adicionando link Mallory (ataque no rb_alice bottleneck)

        self.addLink( mallory, rb_alice, cls= mininet.link.TCLink, **borda )  #eth0 -> #eth3
        #self.addLink( mallory, r2_alice, cls= TCLink, **borda )


def setupHosts(net):

    # Configurando rede

    # rb_alice
    net[ 'r1_alice' ].cmd( 'ifconfig r1_alice-eth0 192.1.1.1 netmask 255.255.255.0' )
    net[ 'r1_alice' ].cmd( 'ifconfig r1_alice-eth1 10.1.1.2 netmask 255.255.255.0' )

    net[ 'r2_alice' ].cmd( 'ifconfig r2_alice-eth0 192.0.0.1 netmask 255.255.255.0' )
    net[ 'r2_alice' ].cmd( 'ifconfig r2_alice-eth1 10.0.0.2 netmask 255.255.255.0' )

    # Alice
    net[ 'alice' ].cmd( 'ifconfig alice-eth0 192.1.1.2 netmask 255.255.255.0' )
    net[ 'alice' ].cmd( 'ifconfig alice-eth1 192.0.0.2 netmask 255.255.255.0' )

    # rb_bob
    net[ 'r3_bob' ].cmd( 'ifconfig r3_bob-eth0 172.1.1.1 netmask 255.255.255.0' )
    net[ 'r3_bob' ].cmd( 'ifconfig r3_bob-eth1 10.1.1.2 netmask 255.255.255.0' )

    net[ 'r4_bob' ].cmd( 'ifconfig r4_bob-eth0 172.0.0.1 netmask 255.255.255.0' )
    net[ 'r4_bob' ].cmd( 'ifconfig r4_bob-eth1 10.0.0.2 netmask 255.255.255.0' )

    # Bob
    net[ 'bob' ].cmd( 'ifconfig bob-eth0 172.1.1.2 netmask 255.255.255.0' )
    net[ 'bob' ].cmd( 'ifconfig bob-eth1 172.0.0.2 netmask 255.255.255.0' )

    # Bottleneck
    net[ 'rb_alice' ].cmd( 'ifconfig rb_alice-eth0 10.1.1.1 netmask 255.255.255.0' )
    net[ 'rb_alice' ].cmd( 'ifconfig rb_alice-eth1 10.0.0.1 netmask 255.255.255.0' )
    net[ 'rb_alice' ].cmd( 'ifconfig rb_alice-eth2 10.10.10.1 netmask 255.255.255.0' )
    net[ 'rb_alice' ].cmd( 'ifconfig rb_alice-eth3 191.1.1.1 netmask 255.255.255.0' )

    net[ 'rb_bob' ].cmd( 'ifconfig rb_bob-eth0 10.1.1.1 netmask 255.255.255.0' )
    net[ 'rb_bob' ].cmd( 'ifconfig rb_bob-eth1 10.0.0.1 netmask 255.255.255.0' )
    net[ 'rb_bob' ].cmd( 'ifconfig rb_bob-eth2 10.10.10.2 netmask 255.255.255.0' )

    #Configurando rotas

    # Alice --> Lan Bob
    net[ 'alice' ].cmd( 'route add -net 172.1.1.0 netmask 255.255.255.0 gw 192.1.1.1' )
    net[ 'alice' ].cmd( 'route add -net 172.0.0.0 netmask 255.255.255.0 gw 192.0.0.1' )

    # Bob -- > Lan Alice
    net[ 'bob' ].cmd( 'route add -net 192.1.1.0 netmask 255.255.255.0 gw 172.1.1.1' )
    net[ 'bob' ].cmd( 'route add -net 192.0.0.0 netmask 255.255.255.0 gw 172.0.0.1' )

    # Router_alice -->  Lan Bob
    net[ 'r1_alice' ].cmd( 'route add -net 172.1.1.0 netmask 255.255.255.0 gw 10.1.1.1' )
    net[ 'r2_alice' ].cmd( 'route add -net 172.0.0.0 netmask 255.255.255.0 gw 10.0.0.1' )

    # Router_bob -->  Lan Alice
    net[ 'r3_bob' ].cmd( 'route add -net 192.1.1.0 netmask 255.255.255.0 gw 10.1.1.1' )
    net[ 'r4_bob' ].cmd( 'route add -net 192.0.0.0 netmask 255.255.255.0 gw 10.0.0.1' )

    # (Bottleneck) rb_alice --> Lan Alice
    net[ 'rb_alice' ].cmd( 'route add -net 192.1.1.0 netmask 255.255.255.0 gw 10.1.1.2' )
    net[ 'rb_alice' ].cmd( 'route add -net 192.0.0.0 netmask 255.255.255.0 gw 10.0.0.2' )
    # (Bottleneck) rb_alice --> Lan Bob
    net[ 'rb_alice' ].cmd( 'route add -net 172.1.1.0 netmask 255.255.255.0 gw 10.10.10.2' )
    net[ 'rb_alice' ].cmd( 'route add -net 172.0.0.0 netmask 255.255.255.0 gw 10.10.10.2' )

    # (Bottleneck) rb_bob --> Lan Bob
    net[ 'rb_bob' ].cmd( 'route add -net 172.1.1.0 netmask 255.255.255.0 gw 10.1.1.2' )
    net[ 'rb_bob' ].cmd( 'route add -net 172.0.0.0 netmask 255.255.255.0 gw 10.0.0.2' )
    # (Bottleneck) rb_bob --> Lan Alice
    net[ 'rb_bob' ].cmd( 'route add -net 192.1.1.0 netmask 255.255.255.0 gw 10.10.10.1' )
    net[ 'rb_bob' ].cmd( 'route add -net 192.0.0.0 netmask 255.255.255.0 gw 10.10.10.1' )

    # CONFIGURANDO ATACANTE

    # mallory
    net[ 'mallory' ].cmd( 'ifconfig mallory-eth0 191.1.1.2 netmask 255.255.255.0' )
    #net[ 'mallory' ].cmd( 'ifconfig mallory-eth1 192.0.0.100 netmask 255.255.255.0' )

    # mallory --> Lan Alice
    #net[ 'mallory' ].cmd( 'route add -net 192.1.1.0 netmask 255.255.255.0 gw 191.1.1.1' )

    # Alice -->  Lan mallory
    #net[ 'alice' ].cmd( 'route add -net 191.1.1.0 netmask 255.255.255.0 gw 192.1.1.1' )

    # mallory --> Lan Bob
    net[ 'mallory' ].cmd( 'route add -net 172.1.1.0 netmask 255.255.255.0 gw 191.1.1.1' )

    # Bob --> Lan mallory
    net[ 'bob' ].cmd( 'route add -net 191.1.1.0 netmask 255.255.255.0 gw 172.1.1.1' )

    # Router_bob --> Lan mallory
    net[ 'r3_bob' ].cmd( 'route add -net 191.1.1.0 netmask 255.255.255.0 gw 10.1.1.1' )

    # (Bottleneck) rb_bob --> Lan mallory
    net[ 'rb_bob' ].cmd( 'route add -net 191.1.1.0 netmask 255.255.255.0 gw 10.10.10.1' )


# Define o minRTO=1s (1000ms) mantendo as mesmas caracteristicas do TCP
def set_interface(net, min_rto_ms):
    # From: https://serverfault.com/questions/529347/how-to-apply-rto-min-to-a-certain-host-in-centos
    for host in ['alice', 'bob']:
        node = net.get(host)
        current_config = node.cmd('ip route show').strip()

        # Alteração no codigo para adicionar o minRTO nas linhas corretas
        array= current_config.split('\r\n')
        for arg in array:
            if arg.find('src') != -1:
                new_config= '%s rto_min %dms' % (arg, min_rto_ms)
                node.cmd('ip route change %s' % new_config, shell=True)

        #new_config = '%s rto_min %dms' % (current_config, min_rto_ms)
        #node.cmd('ip route change %s' % new_config, shell=True)
        node.cmd('ethtool -K {}-eth0 tso off gso off gro off'.format(host))
        node.cmd('ethtool -K {}-eth1 tso off gso off gro off'.format(host))


# Coleta de dados por .pcap
def dumpingAll(host, period, burst):
    host.cmd('tcpdump -i any -n -s 0 -w pcap/{}-{}-{}-all.pcap&'.format(host.name, period, burst))


def run_flow(net, cwnd_file=None):

    alice = net.get('alice')
    bob = net.get('bob')

    print('Starting receiver on {}.'.format(bob.IP()))
    # Execute the receiver with netcat to stay listening at port 12345
    s = bob.popen('./run_receiver.sh', shell=True)

    # Wait for receiver to start listening.
    time.sleep(1.0)

    print('Starting sender on {}.'.format(alice.IP()))
    start = time.time()
    sender_cmd = './run_sender.sh -t {}'.format(bob.IP())

    if cwnd_file is not None:
        sender_cmd += ' -p {}'.format(cwnd_file)

    # check modprobe tcp_probe
    c = alice.popen(sender_cmd, shell=True)
    print('TCP flow started on Alice and Bob.')

    assert c.wait() == 0
    assert s.wait() == 0

    return time.time() - start


def start_attack(net, period, burst):
    mallory = net.get('mallory')
    bob = net.get('bob')
    print('UDP attack started from {} to {}.'.format(mallory.IP(), bob.IP()))

    return mallory.popen([
        'python', 'run_attacker.py', '--period', str(period), '--burst',
        str(burst), '--destination', bob.IP()
    ])


def main():

    parser = argparse.ArgumentParser(description="TCP DoS simulator.")

    parser.add_argument(
        '--burst',
        '-b',
        help="Burst duration in seconds of each DoS attack.",
        type=float,
        default=0.15)

    parser.add_argument(
        '--cong', help="Congestion control algorithm to use.", default='lia')

    parser.add_argument(
        '--suffix',
        '-s',
        help="Suffix for output directory",
        type=str,
        default='default')

    parser.add_argument(
        '--period',
        '-p',
        help="Seconds between low-rate DoS attacks, e.g. 0.5",
        type=float,
        default=0.5)

    parser.add_argument('--rto', '-r', help="rto_min value, in ms", type=int, default=1000)
    args = parser.parse_args()

    # Initialize kernel parameters -- MPTCP
    scheduler= [ "default", "roundrobin", "redundant" ]
    pathmanager= [ "default", "fullmesh", "ndiffports" ]

    subprocess.check_call( 'sysctl -q -w net.mptcp.mptcp_enabled=%i' % 1, shell=True )
    subprocess.check_call( 'sysctl -q -w net.mptcp.mptcp_debug=%i' % 1, shell=True )
    subprocess.check_call( 'sysctl -q -w net.mptcp.mptcp_path_manager=%s' % pathmanager[1], shell=True )
    subprocess.check_call( 'sysctl -q -w net.mptcp.mptcp_scheduler=%s' % scheduler[0], shell=True )

    #Configurações padrão do ataque. Desabilita o fast recovery do TCP    
    subprocess.check_call( 'sysctl -q -w net.ipv4.tcp_congestion_control=%s' % args.cong, shell=True )
    subprocess.check_call( 'sysctl -q -w net.ipv4.tcp_sack=%i' % 0, shell=True )
    subprocess.check_call( 'sysctl -q -w net.ipv4.tcp_dsack=%i' % 0, shell=True )
    subprocess.check_call( 'sysctl -q -w net.ipv4.tcp_fack=%i' % 0, shell=True )
    
    #Desabilita as métricas do roteador, o linux normalmente se lembra dos últimos slow start: https://wiki.linuxfoundation.org/networking/tcp_testing
    #subprocess.check_call( 'sysctl -w net.ipv4.tcp_no_metrics_save=%i' % 1, shell=True )

    topo = Topo()
    net = mininet.net.Mininet(topo=topo, host=mininet.node.CPULimitedHost, link=mininet.link.TCLink, controller=None)
    net.start()
    # Configuracao dos hosts e rotas
    setupHosts(net)
    set_interface(net, args.rto)

    print('\n')
    print('Alice\'s IP is {}.'.format(net.get('alice').IP()))
    print('Bob\'s IP is {}.'.format(net.get('bob').IP()))
    print('Mallory\'s IP is {}.'.format(net.get('mallory').IP()))

    # Abre o terminal do mininet (continua a simulacao quando finalizado)
    mininet.cli.CLI(net)

    output_dir = 'results-{}'.format(args.suffix)

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    time_file = os.path.join(output_dir, 't-{}-{}.txt'.format(args.period, args.burst))
    cwnd_file = os.path.join(output_dir, 'cwnd-{}-{}.txt'.format(args.period, args.burst))

    dumpingAll(net[ 'alice' ], args.period, args.burst )
    dumpingAll(net[ 'bob' ], args.period, args.burst)

    attack = start_attack(net, args.period, args.burst)
    #attack = start_attack(net, 0.1, 20)

    t = run_flow(net, cwnd_file=cwnd_file)

    print('Sending completed in %.4f seconds.' % t)

    with open(time_file, 'w') as f:
        f.write(str(t) + '\n')

    attack.terminate()
    net.stop()


if __name__ == '__main__':
    main()
