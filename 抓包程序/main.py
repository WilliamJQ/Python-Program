import pcap
import dpkt
from dpkt_tools import *
import datetime
import math
import os

# create a sniffer
sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
# sniffer.setfilter('tcp port 80')
print_packets(sniffer)

