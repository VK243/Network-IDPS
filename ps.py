import pcapy
from impacket.ImpactDecoder import EthDecoder, IPDecoder

dev = "Wifi"  # set the device to capture on
max_bytes = 1024  # max number of bytes to capture in each packet
promiscuous = False  # set promiscuous mode to False
timeout = 100  # in milliseconds

# create a pcap object to capture packets
pcap = pcapy.open_live(dev, max_bytes, promiscuous, timeout)

# create decoders to decode packet contents
eth_decoder = EthDecoder()
ip_decoder = IPDecoder()

# loop through captured packets and print their source and destination IP addresses
while True:
    try:
        # capture a packet
        (header, packet) = pcap.next()

        # decode the packet's contents
        eth = eth_decoder.decode(packet)
        ip = ip_decoder.decode(eth.data)

        # print the packet's source and destination IP addresses
        print("Source IP: " + str(ip.get_ip_src()))
        print("Destination IP: " + str(ip.get_ip_dst()))

    except pcapy.PcapError:
        continue
