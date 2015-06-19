pyFirewall
==========

Simple Python Firewall (Linux)
Auto scan your network and detect new ports and you decide locked or unlocked

Install
-------

* pip install scapy
* pip install easygui


Example
-------
default use:

sudo ./pyFirewall.py  # (Caution, default interface is eth0 and rules file is rules.yaml)

or

sudo ./pyFirewall.py -i eth0 -r rules.yaml

You can show in console diferent log -d 0, 1, 2

sudo ./pyFirewall.py -d 2 -i eth0 -r rules.yaml

and console mode without popup:

sudo ./pyFirewall.py -t -i eth0 -r rules.yaml

You can force cleaned to your iptables rules with:

sudo ./pyFirewall.py -f -i eth0 -r rules.yaml

more info

sudo ./pyFirewall.py -h
