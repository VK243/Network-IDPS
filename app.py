import flask
import packet_sniffer
import pandas as pd
import model
import packet_sniffer
from scapy.layers.inet import IP, TCP

app = flask.Flask(__name__)


def packet_sniff():
    # Capture packet data from the packet sniffer code
    packets = packet_sniffer.packet_capture(50)
    
    # initialize a list to store features
    features = []
    # loop through the captured packets and extract desired features
    for packet in packets:
        # initialize a dictionary to store features for each packet
        packet_features = {}

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        
        # extract features
        packet_features['Source IP'] = packet[IP].src
        packet_features['Destination IP'] = packet[IP].dst
        packet_features['Destination Port'] = packet[TCP].dport
        packet_features['Flow Duration'] = packet.time - packets[0].time
        packet_features['Total Length of Fwd Packets'] = packet[TCP].chksum
        packet_features['Fwd Packet Length Min'] = min(packet[TCP].chksum for packet in packets)
        packet_features['Bwd Packet Length Max'] = max(packet[TCP].chksum for packet in packets)
        packet_features['Bwd Packet Length Min'] = min(packet[TCP].chksum for packet in packets)
        packet_features['Bwd Packet Length Mean'] = sum(packet[TCP].chksum for packet in packets)/len(packets)
        packet_features['Bwd Packet Length Std'] = pd.Series([packet[TCP].chksum for packet in packets]).std()
        packet_features['Flow IAT Mean'] = (packet.time - packets[0].time)/len(packets)
        packet_features['Flow IAT Std'] = pd.Series([packet.time - packets[i-1].time for i in range(1,len(packets))]).std()
        packet_features['Flow IAT Max'] = max(packet.time - packets[i-1].time for i in range(1,len(packets)))
        packet_features['Flow IAT Min'] = min(packet.time - packets[i-1].time for i in range(1,len(packets)))
        packet_features['Fwd IAT Total'] = sum(packet.time - packets[i-1].time for i in range(1,len(packets)))
        packet_features['Fwd IAT Mean'] = (packet.time - packets[0].time)/(len(packets)-1)
        packet_features['Fwd IAT Std'] = pd.Series([packet.time - packets[i-1].time for i in range(2,len(packets))]).std()
        packet_features['Fwd IAT Max'] = max(packet.time - packets[i-1].time for i in range(2,len(packets)))
        packet_features['Bwd IAT Mean'] = (packet.time - packets[1].time)/(len(packets)-1)
        packet_features['Bwd IAT Std'] = pd.Series([packet.time - packets[i-1].time for i in range(3,len(packets))]).std()
        packet_features['Bwd IAT Max'] = max(packet.time - packets[i-1].time for i in range(3,len(packets)))
        packet_features['Bwd IAT Min'] = min(packet.time - packets[i-1].time for i in range(3,len(packets)))
        packet_features['Fwd PSH Flags'] = packet[TCP].flags & 0x08
        packet_features['Bwd Packets/s'] = len(packets) / (packet.time - packets[0].time) if (packet.time - packets[0].time) != 0 else 0
        packet_features['Min Packet Length'] = min(packet[TCP].chksum for packet in packets)
        packet_features['Packet Length Mean'] = sum(packet[TCP].chksum for packet in packets)/len(packets)
        packet_features['Packet Length Std'] = pd.Series([packet[TCP].chksum for packet in packets]).std()
        packet_features['Packet Length Variance'] = pd.Series([packet[TCP].chksum for packet in packets]).var()
        packet_features['FIN Flag Count'] = sum(1 for packet in packets if packet[TCP].flags & 0x01)
        packet_features['SYN Flag Count'] = sum(1 for packet in packets if packet[TCP].flags & 0x02)
        packet_features['PSH Flag Count'] = sum(1 for packet in packets if packet[TCP].flags & 0x08)
        packet_features['ACK Flag Count'] = sum(1 for packet in packets if packet[TCP].flags & 0x10)
        packet_features['URG Flag Count'] = sum(1 for packet in packets if packet[TCP].flags & 0x20)
        packet_features['Down/Up Ratio'] = len([packet for packet in packets if packet[IP].src == source_ip])/len([packet for packet in packets if packet[IP].src == dest_ip])
        packet_features['Average Packet Size'] = sum(packet[TCP].chksum for packet in packets)/len(packets)
        packet_features['Avg Bwd Segment Size'] = sum(packet[TCP].chksum for packet in packets if packet[TCP].seq < packet[TCP].ack)/len(packets)
        packet_features['Subflow Fwd Bytes'] = sum(packet[TCP].chksum for packet in packets if packet[TCP].seq > packet[TCP].ack)
        packet_features['Init_Win_bytes_forward'] = packets[0][TCP].window
        packet_features['Active Mean'] = pd.Series([packet.time - packets[i-1].time for i in range(1,len(packets))]).mean()
        packet_features['Active Std'] = pd.Series([packet.time - packets[i-1].time for i in range(1,len(packets))]).std()
        packet_features['Active Max'] = pd.Series([packet.time - packets[i-1].time for i in range(1,len(packets))]).max()
        packet_features['Active Min'] = pd.Series([packet.time - packets[i-1].time for i in range(1,len(packets))]).min()
        packet_features['Idle Mean'] = pd.Series([packets[i+1].time - packet.time for i, packet in enumerate(packets[:-1])]).mean()
        packet_features['Idle Std'] = pd.Series([packets[i+1].time - packet.time for i, packet in enumerate(packets[:-1])]).std()
        packet_features['Idle Max'] = pd.Series([packets[i+1].time - packet.time for i, packet in enumerate(packets[:-1])]).max()
        packet_features['Idle Min'] = pd.Series([packets[i+1].time - packet.time for i, packet in enumerate(packets[:-1])]).min()

        # append the packet features to the list of features
        features.append(packet_features)
        
    # create a pandas dataframe from the features
    df = pd.DataFrame(features)
    return df

def data():
    packet_data_df = packet_sniff()

    predictions = model.predict(packet_data_df[0])

    return packet_data_df, predictions


@app.route('/')
def home():
    
    # Render the predictions and packet data in a Jinja2 template
    packet_data_df, predictions = data()

    return flask.render_template('index.html', packets=packet_data_df, predictions=predictions)


if __name__ == '__main__':
    app.run(debug=True)
