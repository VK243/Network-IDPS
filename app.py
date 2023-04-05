import streamlit as st 
from scapy.all import *
from scapy.layers.inet import IP, TCP
import tensorflow as tf
import numpy as np
import pandas as pd
# import PacketSniffer
from fast_ml.utilities import reduce_memory_usage


data = pd.read_csv("data.csv",index_col="Unnamed: 0")
model = tf.keras.models.load_model('models\keras_model_v5.h5')
data = reduce_memory_usage(data, convert_to_category=False)
prediction = model.predict(data)
y_pred = np.argmax(prediction, axis=-1)
st.write(y_pred)