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
try:
    import yaml
except Exception, e:
    print "You need install yaml python module"
    raise
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
debug_mode = 0
text_mode = False
force_clean = False
conf = {}
c = 0
my_ip = socket.gethostbyname(socket.gethostname())


def usage():
    print """
%s -t -f [-d <debug level 0-2 default 0>] -i <interface> -r <rules.yaml>
-d debug level 0 = only show new port detect
               1 = include locked port
               2 = include unlocked port
-t text mode no used popup only console mode.
-f force clean my iptables rules
version 0.1 by Endika Iglesias <me@endikaiglesias.com>
          """ % (sys.argv[0])
    sys.exit(2)


def save_conf():
    global conf
    global LOG_FILE
    with open(LOG_FILE, 'w') as outfile:
        outfile.write(yaml.dump(conf, default_flow_style=False))


def _clean_iptables():
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
        management_rules(add=False)
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


def management_rules(add=True):
    global conf
    add = '-A' if add else '-D'
    for a in conf.keys():
        if a == 'RANGE':
            for proto in conf['RANGE'].keys():
                for tupla in conf['RANGE'][proto]:
                    if tupla[2]:  # Only DROP ports
                        action = 'DROP' if tupla[2] else 'ACCEPT'
                        os.system(
                            'iptables %s INPUT -p %s --sport %s -j %s' % (
                                add, proto,
                                str(tupla[0]) + ':' + str(tupla[1]), action))
                        # os.system(
                        #     'iptables -A INPUT -p %s --dport %s -j %s' % (
                        #         proto,
                        #         str(tupla[0]) + ':' + str(tupla[1]), action))
        else:
            for p in conf[a].keys():
                if conf[a][p]:  # Only DROP ports
                    action = 'DROP' if conf[a][p] else 'ACCEPT'
                    os.system('iptables %s INPUT -p %s --sport %s -j %s' % (
                        add, proto, p, action))
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
        conf['RANGE']['TCP'] = [(60000, 65535, True)]
        conf['RANGE']['UDP'] = [(60000, 65535, True)]
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
    global text_mode
    msg = None
    level = 0
    if hasattr(p, 'dport'):
        unknown, drop, port = check_port(p)
        if unknown and port > 0:
            msg = 'NEW     '
            b_port = str(port) + ' ' * int(5 - len(str(port)))
            print "#%s::%s - %s::%s" % (c, msg, b_port, p.summary())
            if not text_mode:
                drop = easygui.ynbox(
                    ('New port detect %s \n %s' % (port, p.summary())),
                    'Block', ('Locked', 'Unlocked'))
            else:
                option = None
                while option != 'y' and option != 'n':
                    option = raw_input(
                        'New port detect %s \n%s '
                        '\nYou locked this port [y/n]' % (
                            port, p.summary())).lower()
                drop = option == 'y'
            if TCP in p:
                conf['TCP'][port] = drop == 1
            elif UDP in p:
                conf['UDP'][port] = drop == 1
            save_conf()
            management_rules()
        if drop and port > 0:
            msg = 'LOCKED  '
            level = 1
        else:
            msg = 'UNLOCKED'
            level = 2
    if msg:
        if debug_mode >= level:
            b_port = str(port) + ' ' * int(5 - len(str(port)))
            print "#%s::%s - %s::%s" % (c, msg, b_port, p.summary())
    c += 1


def init():
    global LOG_FILE
    global debug_mode
    global text_mode
    global force_clean
    interface = 'eth0'
    try:
        options, remainder = getopt.getopt(
            sys.argv[1:], 'i:r:ti:td:ft:di:',
            ['interface=', 'rules=', 'debug='])
    except getopt.GetoptError:
        usage()
    for opt, arg in options:
        if opt in ('-i', '--interface'):
            interface = arg
        elif opt in ('-r', '--rules'):
            LOG_FILE = arg
        elif opt in ('-d', '--debug'):
            try:
                debug_mode = int(arg)
            except Exception:
                debug_mode = 0
        elif opt in ('-t'):
            text_mode = True
        elif opt in ('-f', '--force'):
            force_clean = True
        else:
            usage()
    return interface

interface = init()
load_conf()
if force_clean:
    _clean_iptables()
management_rules()
sniff(iface=interface, prn=check_packets)
