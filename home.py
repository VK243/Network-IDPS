import streamlit as st 
import pandas  as pd
from app import *
from PacketSniffer import *

st.set_page_config(layout='wide')

st.title('Network Packet Analyzer')
n = st.number_input("Enter No of Packet:")

def main():
    if st.button("Capture Packet"):
        df = packet_capture(n)
        df = df.drop(['Source IP', 'Destination IP'], axis=1)
        df.to_csv('data.csv')
        pred_df = pd.DataFrame(predict(), columns=['Prediction'])
        df = pd.concat([df,pred_df],axis='columns')
        def style_row(row):
            if row['Prediction'] == 0:
                return ['background-color: green'] * len(row)
            elif row['Prediction'] == 1:
                return ['background-color: red'] * len(row)
            else:
                return [''] * len(row)

        st.dataframe(df.style.apply(style_row, axis=1))

if __name__ == '__main__':
    main()
