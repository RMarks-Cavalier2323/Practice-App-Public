import json
from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

@app.route("/")
def home():
    # Load analyzed data
    df = pd.read_csv("analyzed_data.csv")

    # Debugging: Check the unique values in the 'Anomaly' column to ensure 'Anomaly' is present
    print("Unique values in Anomaly column:", df['Anomaly'].unique())  # Debugging: check Anomaly values

    # Convert DataFrame to list of dictionaries for HTML rendering
    data = df.to_dict(orient="records")

    # Ensure 'Packet_Length' and 'Timestamp' exist in the DataFrame
    if 'Packet_Length' in df.columns and 'Timestamp' in df.columns:
        # Convert Packet_Length to numeric, in case it is not
        df['Packet_Length'] = pd.to_numeric(df['Packet_Length'], errors='coerce')

        # Filter for anomalies and drop NaN values
        scatter_data = df[df['Anomaly'] == 'Anomaly'][['Packet_Length', 'Timestamp']].dropna()

        # Debugging: Log scatter data before passing it to the template
        print("Scatter Data being passed to template:", scatter_data)  # Debugging: check scatter data

        # Convert Timestamp to UNIX timestamp (in milliseconds) for Chart.js compatibility
        scatter_data['Timestamp'] = pd.to_datetime(scatter_data['Timestamp']).apply(lambda x: x.timestamp() * 1000)

        # Debugging: Check the converted Timestamp values
        print("Converted Timestamps for Chart.js:", scatter_data['Timestamp'])  # Debugging: check Timestamp conversion

        # Convert data into JSON for use in JavaScript
        scatter_data_json = scatter_data.to_dict(orient="records") if not scatter_data.empty else []
    else:
        scatter_data_json = []  # Set empty list if columns are missing

    return render_template("index.html", columns=df.columns, data=data, scatter_data=scatter_data_json)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
