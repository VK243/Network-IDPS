import streamlit as st 
import tensorflow as tf
import numpy as np
import pandas as pd
from fast_ml.utilities import reduce_memory_usage

# st.set_page_config(layout='wide')

# @st.cache_resource
# def model(df):
    
#     # Load the pre-trained model from .h5 file
#     model = tf.keras.models.load_model('models\keras_model_v1_2.h5')

#     # Define a function to preprocess input data
#     def preprocess_input(input_data):
        
#         # Perform any necessary preprocessing here
#         # input_data = reduce_memory_usage(input_data, convert_to_category=False)
        
#         return input_data

#     # Define a function to predict the class of a network packet
#     def predict(packet):
#         # Preprocess the packet data
#         preprocessed_packet = preprocess_input(packet)
#         # Make a prediction using the pre-trained model
#         prediction = model.predict(preprocessed_packet)
#         # Return the predicted class
#         return np.argmax(prediction, axis=-1)
    
#     predict(df)

data = pd.read_csv("data.csv",index_col="Unnamed: 0")
model = tf.keras.models.load_model('models\keras_model_v5.h5')
data = reduce_memory_usage(data, convert_to_category=False)
prediction = model.predict(data)
y_pred = np.argmax(prediction, axis=-1)
st.write(y_pred)

# features = PacketSniffer.packet_capture(5)

# # create a pandas dataframe from the features
# df = pd.DataFrame(features)
# st.write(df)

 

# data = df.drop(['Source IP', 'Destination IP'], axis=1)


# pre = model(data.iloc[1])
# st.write(pre)
# #data.to_csv("data.csv")
# # st.write((data.dtypes))
# # st.write(data.shape)









