import os
import pandas as pd
from flask import Flask, render_template, redirect, url_for, session
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

# Set redirect URI based on environment (Render or Local)
if IS_LOCAL:
    REDIRECT_URI = "http://localhost:5000/authorize"  # Local development URL
else:
    REDIRECT_URI = "https://practice-app-ynj3.onrender.com/authorize"  # Render production URL

JS_ORIGIN = REDIRECT_URI.split("/authorize")[0]

# Debugging: Print the redirect URI
print(f"Using redirect URI: {REDIRECT_URI}")

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
    try:
        # Get user session data
        user = session.get("user", None)

        # If on Render and no user session, redirect to login
        if not IS_LOCAL and not user:
            return redirect(url_for("login"))

        # Email from session (if available)
        email = user.get("userinfo", {}).get("email", "Not logged in") if user else "Not logged in"
        print(f"Logged in as: {email}")

        # Load CSV data
        df = pd.read_csv("analyzed_data.csv")
        print(f"Data loaded successfully with columns: {df.columns}")
        data = df.to_dict(orient="records")

        # Scatter data processing
        if 'Packet_Length' in df.columns and 'Timestamp' in df.columns:
            df['Packet_Length'] = pd.to_numeric(df['Packet_Length'], errors='coerce')
            scatter_data = df[df['Anomaly'] == 'Anomaly'][['Packet_Length', 'Timestamp']].dropna()
            scatter_data['Timestamp'] = pd.to_datetime(scatter_data['Timestamp']).apply(lambda x: x.timestamp() * 1000)
            scatter_data_json = scatter_data.to_dict(orient="records") if not scatter_data.empty else []
            print(f"Scatter data prepared with {len(scatter_data)} anomalies")
        else:
            scatter_data_json = []
            print("No 'Packet_Length' or 'Timestamp' columns found.")

        # Pass 'is_render' flag to template to control login visibility and show data only if logged in
        return render_template("index.html", columns=df.columns, data=data, scatter_data=scatter_data_json, email=email, is_render=not IS_LOCAL)

    except Exception as e:
        print(f"Error loading data: {e}")
        return "Error loading data", 500

@app.route("/login")
def login():
    # Only allow OAuth login if the app is running on Render
    if not IS_LOCAL:
        print(f"Redirecting to Google OAuth with redirect URI: {REDIRECT_URI}")
        return google.authorize_redirect(REDIRECT_URI)
    else:
        return redirect(url_for("home"))

@app.route("/authorize")
def authorize():
    try:
        print("Attempting to authorize and retrieve the access token")
        token = google.authorize_access_token()
        session["user"] = token
        print(f"Authorization successful, user session set: {session.get('user')}")
        return redirect(url_for("home"))
    except Exception as e:
        print(f"OAuth authorization failed: {e}")
        return "OAuth authorization failed", 500

@app.route("/logout")
def logout():
    print("Logging out user")
    session.pop("user", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(debug=True, host="0.0.0.0", port=5000)
