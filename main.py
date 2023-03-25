import streamlit as st 
from scapy.all import *
from scapy.layers.inet import IP, TCP
import tensorflow as tf
import numpy as np
import pandas as pd
import PacketSniffer

st.set_page_config(layout='wide')

@st.cache_resource
def model(df):
    
    # Load the pre-trained model from .h5 file
    model = tf.keras.models.load_model('models\keras_model_v1_2.h5')

    # Define a function to preprocess input data
    def preprocess_input(input_data):
        
        # Perform any necessary preprocessing here
        input_data = input_data.astype('float32')
        
        return input_data

    # Define a function to predict the class of a network packet
    def predict(packet):
        # Preprocess the packet data
        preprocessed_packet = preprocess_input(packet)
        # Make a prediction using the pre-trained model
        prediction = model.predict(np.array([preprocessed_packet]))
        # Return the predicted class
        return np.argmax(prediction)
    predict(df)
 

# capture (Any) packets and extract features
features = PacketSniffer.packet_capture(5)

# create a pandas dataframe from the features
df = pd.DataFrame(features)
st.write(df)

 
# Only 36 features 
data = df.drop(['Source IP', 'Destination IP'], axis=1)


# Loop to send the packet data to the model to predict


pre = model(data.iloc[1])
st.write(pre)

st.write((data.dtypes))
st.write(data.shape)









