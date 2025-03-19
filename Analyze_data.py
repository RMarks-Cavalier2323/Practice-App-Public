import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

def anomaly_detection(data):
    # Select numerical columns only for anomaly detection
    numeric_columns = ["Packet_Length", "Source_IP_Encoded", "Destination_IP_Encoded", "Protocol_Encoded"]
    numeric_data = data[numeric_columns]

    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(numeric_data)

    # Predict anomalies (1 = normal, -1 = anomaly)
    predictions = clf.predict(numeric_data)
    
    # Convert -1 to "Anomaly" and 1 to "Normal" for readability
    data["Anomaly"] = np.where(predictions == -1, "Anomaly", "Normal")
    
    return data

if __name__ == "__main__":
    # Load the extracted data
    df = pd.read_csv("extracted_data.csv")

    # Ensure categorical data is properly encoded for model input
    label_encoder = LabelEncoder()
    df["Source_IP_Encoded"] = label_encoder.fit_transform(df["Source_IP"])
    df["Destination_IP_Encoded"] = label_encoder.fit_transform(df["Destination_IP"])
    df["Protocol_Encoded"] = label_encoder.fit_transform(df["Protocol"])

    # Perform anomaly detection
    df = anomaly_detection(df)

    # Save the analyzed data
    df.to_csv("analyzed_data.csv", index=False)
    print("Analyzed data saved to analyzed_data.csv")

