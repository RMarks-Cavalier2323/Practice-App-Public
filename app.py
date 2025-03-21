import os
import pandas as pd
from flask import Flask, render_template, session, redirect, url_for, g
import logging

# Configure Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Logger setup
logging.basicConfig(level=logging.INFO)

# Function to load data from CSV file
def load_data():
    try:
        data = pd.read_csv("analyzed_data.csv")
        logging.info(f"Data loaded successfully with columns: {data.columns}")
        return data
    except Exception as e:
        logging.error(f"Error loading data from CSV: {e}")
        return pd.DataFrame()  # Return empty DataFrame in case of error

# Function to prepare scatter data
def prepare_scatter_data(data):
    if "Packet_Length" in data.columns and "Timestamp" in data.columns:
        data["Packet_Length"] = pd.to_numeric(data["Packet_Length"], errors="coerce")
        scatter_data = data[data["Anomaly"] == "Anomaly"][["Packet_Length", "Timestamp"]].dropna()
        scatter_data["Timestamp"] = pd.to_datetime(scatter_data["Timestamp"]).apply(lambda x: x.timestamp() * 1000)
        return scatter_data.to_dict(orient="records") if not scatter_data.empty else []
    return []

# Route for the home page
@app.route('/')
def index():
    try:
        # Simulating local login status (can be replaced with actual authentication logic if needed)
        g.is_local = True  # Change this flag if using an actual login system
        
        # Load data from the CSV file
        data = load_data()

        if data.empty:
            return "Error loading data", 500

        # Prepare scatter data based on loaded data
        scatter_data = prepare_scatter_data(data)

        # Get column names for the table
        columns = data.columns.tolist()

        # Log the data for debugging
        logging.info(f"Data: {data}")
        logging.info(f"Scatter data: {scatter_data}")

        # If user is local or logged in, render data
        if g.is_local or 'user' in session:
            return render_template('index.html', data=data.to_dict(orient='records'), columns=columns, scatter_data=scatter_data)
        else:
            return redirect(url_for('login'))

    except Exception as e:
        logging.error(f"Error in index route: {e}")
        return "Error occurred", 500

# Simulating a login route (can be replaced with actual login logic)
@app.route('/login')
def login():
    # Simulate login logic here (or use OAuth if required)
    return "Login Page (For demonstration purposes)"

# Run the app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
