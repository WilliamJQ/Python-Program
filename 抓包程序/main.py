import pcap
import dpkt
from dpkt_tools import *
import datetime
import math
import os

# create a sniffer
sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
sniffer.setfilter('ip src host 221.192.237.140')
print_packets(sniffer)

