import os
import json
import pandas as pd
from flask import Flask, render_template, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Load secret key and OAuth credentials from environment variables
app.secret_key = os.getenv("SECRET_KEY", "your_default_secret_key")
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")

# Determine if app is running locally or on Render
IS_LOCAL = os.getenv("LOCAL_DEV", "false").lower() == "true"

# Set correct redirect URI dynamically
if IS_LOCAL:
    REDIRECT_URI = "http://localhost:5000/authorize"
    JS_ORIGIN = "http://localhost:5000"
else:
    REDIRECT_URI = "https://practice-app-ynj3.onrender.com/authorize"
    JS_ORIGIN = "https://practice-app-ynj3.onrender.com"

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=OAUTH_CLIENT_ID,
    client_secret=OAUTH_CLIENT_SECRET,
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'scope': 'openid email profile'},
    client_kwargs={'redirect_uri': REDIRECT_URI},
)

@app.route("/")
def home():
    df = pd.read_csv("analyzed_data.csv")
    data = df.to_dict(orient="records")

    if 'Packet_Length' in df.columns and 'Timestamp' in df.columns:
        df['Packet_Length'] = pd.to_numeric(df['Packet_Length'], errors='coerce')
        scatter_data = df[df['Anomaly'] == 'Anomaly'][['Packet_Length', 'Timestamp']].dropna()
        scatter_data['Timestamp'] = pd.to_datetime(scatter_data['Timestamp']).apply(lambda x: x.timestamp() * 1000)
        scatter_data_json = scatter_data.to_dict(orient="records") if not scatter_data.empty else []
    else:
        scatter_data_json = []

    return render_template("index.html", columns=df.columns, data=data, scatter_data=scatter_data_json)

@app.route("/login")
def login():
    return google.authorize_redirect(REDIRECT_URI)

@app.route("/authorize")
def authorize():
    token = google.authorize_access_token()
    session["user"] = token
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
