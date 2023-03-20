from scapy.all import *


# create a function to capture packets and extract features
def packet_capture(packet_count):
    
    # define a filter to capture only TCP packets
    filter = "tcp and ip"
    
    # capture packets using the filter
    packets = sniff(count=packet_count, filter=filter)

    # return the packets
    return packets

