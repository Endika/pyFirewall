#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from scapy.all import TCP, UDP, sniff
except Exception, e:
    print "You need install scapy python module"
    raise
try:
    import easygui
except Exception, e:
    print "You need install easygui python module"
    raise
import yaml
import os
import socket
import signal
import sys
import errno
import getopt

if os.getuid() != 0:
    print "You need root user"
    sys.exit(0)

LOG_FILE = 'rules.yaml'
debug_mode = False
conf = {}
c = 0
my_ip = socket.gethostbyname(socket.gethostname())


def usage():
    print """
%s [-d] -i <interface> -r <rules.yaml>
version 0.1 by Endika Iglesias <me@endikaiglesias.com>
          """ % (sys.argv[0])
    sys.exit(2)


def save_conf():
    global conf
    global LOG_FILE
    with open(LOG_FILE, 'w') as outfile:
        outfile.write(yaml.dump(conf, default_flow_style=False))


def clean_iptables():
    # Clean All RULES
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('iptables -t mangle -F')
    os.system('iptables -t mangle -X')
    os.system('iptables -P INPUT ACCEPT')
    os.system('iptables -P FORWARD ACCEPT')
    os.system('iptables -P OUTPUT ACCEPT')


def signal_handler(signal, frame):
        clean_iptables()
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


def create_rules():
    global conf
    for a in conf.keys():
        if a == 'RANGE':
            for proto in conf['RANGE'].keys():
                for tupla in conf['RANGE'][proto]:
                    if tupla[2]:  # Only DROP ports
                        action = 'DROP' if tupla[2] else 'ACCEPT'
                        os.system(
                            'iptables -A INPUT -p %s --sport %s -j %s' % (
                                proto,
                                str(tupla[0]) + ':' + str(tupla[1]), action))
                        # os.system(
                        #     'iptables -A INPUT -p %s --dport %s -j %s' % (
                        #         proto,
                        #         str(tupla[0]) + ':' + str(tupla[1]), action))
        else:
            for p in conf[a].keys():
                if conf[a][p]:  # Only DROP ports
                    action = 'DROP' if conf[a][p] else 'ACCEPT'
                    os.system('iptables -A INPUT -p %s --sport %s -j %s' % (
                        proto, p, action))
                    # os.system('iptables -A INPUT -p %s --dport %s -j %s' % (
                    #     proto, p, action))


def load_conf():
    global conf
    global LOG_FILE
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        os.open(LOG_FILE, flags)
    except OSError as e:
        if e.errno == errno.EEXIST:  # Failed as the file already exists.
            pass
        else:  # Something unexpected went wrong so reraise the exception.
            raise
    document = open(LOG_FILE).read()
    conf = yaml.load(document)
    if conf is None:
        # Default configuration
        conf = {}
        conf['RANGE'] = {}
        conf['RANGE']['TCP'] = [(17500, 65535, True)]
        conf['RANGE']['UDP'] = [(17500, 65535, True)]
        conf['TCP'] = {80: False, 443: False}
        conf['UDP'] = {80: False, 443: False}
        save_conf()


def check_port(packet):
    global my_ip
    global conf
    unknown = True
    drop = True
    port = 0
    if my_ip != packet[1].dst:
        if UDP in packet:
            if packet.dport in conf['UDP'].keys():
                unknown = False
                drop = conf['UDP'][packet.dport]
            port = packet.dport
        elif TCP in packet:
            if packet.dport in conf['TCP'].keys():
                unknown = False
                drop = conf['TCP'][packet.dport]
            port = packet.dport
    if my_ip != packet[1].src:
        if unknown:
            if UDP in packet:
                if packet.sport in conf['UDP'].keys():
                    unknown = False
                    drop = conf['UDP'][packet.sport]
                port = packet.sport
            elif TCP in packet:
                if packet.sport in conf['TCP'].keys():
                    unknown = False
                    drop = conf['TCP'][packet.sport]
                port = packet.sport
    if my_ip != packet[1].dst:
        if unknown:
            if TCP in packet:
                for tupla in conf['RANGE']['TCP']:
                    if packet.dport in xrange(tupla[0], tupla[1]):
                        unknown = False
                        drop = tupla[2]
                        break
                port = packet.dport
            elif UDP in packet:
                for tupla in conf['RANGE']['UDP']:
                    if packet.dport in xrange(tupla[0], tupla[1]):
                        unknown = False
                        drop = tupla[2]
                        break
                port = packet.dport
    if my_ip != packet[1].src:
        if unknown:
            if TCP in packet:
                for tupla in conf['RANGE']['TCP']:
                    if packet.sport in xrange(tupla[0], tupla[1]):
                        unknown = False
                        drop = tupla[2]
                        break
                port = packet.sport
            elif UDP in packet:
                for tupla in conf['RANGE']['UDP']:
                    if packet.sport in xrange(tupla[0], tupla[1]):
                        unknown = False
                        drop = tupla[2]
                        break
                port = packet.sport
    return unknown, drop, port


def check_packets(p):
    global c
    global conf
    msg = None
    if hasattr(p, 'dport'):
        unknown, drop, port = check_port(p)
        if unknown and port > 0:
            msg = 'NEW     '
            b_port = str(port) + ' ' * int(5 - len(str(port)))
            print "#%s::%s - %s::%s" % (c, msg, b_port, p.summary())
            drop = easygui.ynbox(
                ('New port detect %s \n %s' % (port, p.summary())),
                'Block', ('Locked', 'Unlocked'))
            if TCP in p:
                conf['TCP'][port] = drop == 1
            elif UDP in p:
                conf['UDP'][port] = drop == 1
            save_conf()
            clean_iptables()
            create_rules()
        if drop and port > 0:
            msg = 'LOCKED  '
        else:
            msg = 'UNLOCKED'
    if msg:
        if msg == 'LOCKED  ' or debug_mode:
            b_port = str(port) + ' ' * int(5 - len(str(port)))
            print "#%s::%s - %s::%s" % (c, msg, b_port, p.summary())
    c += 1


def init():
    global LOG_FILE
    global debug_mode
    interface = 'eth0'
    try:
        options, remainder = getopt.getopt(sys.argv[1:], 'i:r:h:ird:id:rd',
                                           ['interface=', 'rules='])
    except getopt.GetoptError:
        usage()

    for opt, arg in options:
        if opt in ('-i', '--interface'):
            interface = arg
        elif opt in ('-r', '--rules'):
            LOG_FILE = arg
        elif opt in ('-d', '--debug'):
            debug_mode = True
        else:
            usage()
    return interface

interface = init()
load_conf()
clean_iptables()
create_rules()
sniff(iface=interface, prn=check_packets)
