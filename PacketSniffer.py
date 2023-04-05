from scapy.all import *
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP
import streamlit as st 

# create a function to capture packets and extract features
def packet_capture(packet_count):
    # initialize a list to store features
    features = []
    
    # define a filter to capture only TCP packets
    filter = "tcp and ip"
    
    # capture packets using the filter
    packets = sniff(count=packet_count, filter=filter)
    
    # loop through the captured packets and extract desired features
    for packet in packets:
        # initialize a dictionary to store features for each packet
        packet_features = {}

        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
        else:
            source_ip = " "
            dest_ip = " " 
            
        # extract features
    
        packet_features['Source IP'] = packet[IP].src
        packet_features['Destination IP'] = packet[IP].dst
        
        packet_features['Destination Port'] = packet[TCP].dport
        packet_features['Flow Duration'] = packets[-1].time - packets[0].time if len(packets) > 0 else 0
        packet_features['Total Length of Fwd Packets'] = sum(packet[IP].len for packet in packets if packet[IP].src == source_ip)
        packet_features['Fwd Packet Length Min'] = min(packet[IP].len for packet in packets if packet[IP].src == source_ip)
        packet_features['Fwd Packet Length Max'] = max(packet[IP].len for packet in packets if packet[IP].src == source_ip)
        packet_features['Fwd Packet Length Mean'] = pd.Series([packet[IP].len for packet in packets if packet[IP].src == source_ip]).mean()
        
        fwd_pk_std = pd.Series([packet[IP].len for packet in packets if packet[IP].src == source_ip]).std()
        if fwd_pk_std == None:
            packet_features['Fwd Packet Length Std'] = 0
        else:
            packet_features['Fwd Packet Length Std'] = fwd_pk_std
            
        packet_lengths = [packet[IP].len for packet in packets if packet.haslayer(IP) and packet[IP].src == dest_ip]
        if packet_lengths:
            packet_features['Bwd Packet Length Min'] = min(packet_lengths)
        else:
            packet_features['Bwd Packet Length Min'] = 0
            
        packet_back = [packet[IP].len for packet in packets if packet[IP].src == dest_ip]
        if packet_back:
            packet_features['Bwd Packet Length Max'] = max(packet_back)
        else:
            packet_features['Bwd Packet Length Max'] = 0
        
        packet_features['Bwd Packet Length Mean'] = pd.Series([packet[IP].len for packet in packets if packet[IP].src == dest_ip]).mean()
        packet_features['Bwd Packet Length Std'] = pd.Series([packet[IP].len for packet in packets if packet[IP].src == dest_ip]).std()
        packet_features['Flow IAT Mean'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0]).mean()
        packet_features['Flow IAT Std'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0]).std()
        packet_features['Flow IAT Max'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0]).max()
        packet_features['Flow IAT Min'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0]).min()
        packet_features['Fwd IAT Total'] = sum(packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == source_ip)
        packet_features['Fwd IAT Mean'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == source_ip]).mean()
        fwd_iat_std = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == source_ip]).std()
        
        if fwd_iat_std:
            packet_features['Fwd IAT Std'] = fwd_iat_std
        else:
            packet_features['Fwd IAT Std'] = 0
            
        packet_features['Fwd IAT Max'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == source_ip]).max()
        packet_features['Fwd IAT Min'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == source_ip]).min()
        packet_features['Bwd IAT Total'] = sum(packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == dest_ip)
        packet_features['Bwd IAT Mean'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == dest_ip]).mean()
        packet_features['Bwd IAT Std'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == dest_ip]).std()
        packet_features['Bwd IAT Max'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == dest_ip]).max()
        packet_features['Bwd IAT Min'] = pd.Series([packet.time - packets[i-1].time for i, packet in enumerate(packets) if i > 0 and packet[IP].src == dest_ip]).min()
        packet_features['Fwd Header Length'] = packet[TCP].dataofs * 4
        packet_features['Bwd Header Length'] = packet[TCP].dataofs * 4
        
        if packet_features['Flow Duration'] == 0:
            packet_features['Fwd Packets/s'] = 0
        else:
            packet_features['Fwd Packets/s'] = len([packet for packet in packets if packet[IP].src == source_ip]) / packet_features['Flow Duration']
        
        packet_features['Bwd Packets/s'] = len([packet for packet in packets if packet[IP].src == dest_ip]) / packet_features['Flow Duration']
        packet_features['Total Fwd Packets'] = sum(1 for packet in packets if packet[IP].src == source_ip)
        packet_features['Total Backward Packets'] = sum(1 for packet in packets if packet[IP].src == dest_ip)
        packet_features['Total Length of Bwd Packets'] = sum(packet[IP].len for packet in packets if packet[IP].src == dest_ip)
        packet_features['Flow Bytes/s'] = sum(packet[IP].len for packet in packets if packet[IP].src == source_ip) / (packets[-1].time - packets[0].time)
        packet_features['Flow Packets/s'] = sum(1 for packet in packets if packet[IP].src == source_ip) / (packets[-1].time - packets[0].time)
        packet_features['Fwd PSH Flags'] = sum(1 for packet in packets if packet.haslayer(TCP) and packet.haslayer(IP) and packet[IP].src == source_ip and packet[TCP].flags and 'PSH' in packet[TCP].flags)
        packet_features['Min Packet Length'] = min(packet[IP].len for packet in packets if packet[IP].src == source_ip)

        # append the packet features to the list of features
        features.append(packet_features)
        
    features = pd.DataFrame(features)
    # Forward fill NaN values with the value from the previous row
    features = features.fillna(method='ffill',axis=1)
    
    # return the list of features
    return features

num = st.number_input("Enter number of Packets:")
df = packet_capture(num)
st.write(df)
df = df.drop(['Source IP', 'Destination IP'], axis=1)
df.to_csv('data.csv')