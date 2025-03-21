import os
import pandas as pd
from flask import Flask, render_template, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask_session import Session

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Load secret key and OAuth credentials from environment variables
app.secret_key = os.getenv("SECRET_KEY", "your_default_secret_key")
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")

# Debugging: Log the Client ID (Never log secrets in production!)
print(f"OAUTH_CLIENT_ID loaded: {bool(OAUTH_CLIENT_ID)}")
print(f"OAUTH_CLIENT_SECRET loaded: {bool(OAUTH_CLIENT_SECRET)}")

# Determine if app is running locally or on Render
IS_LOCAL = os.getenv("LOCAL_DEV", "false").lower() == "true"

# Configure Flask session storage
app.config["SESSION_TYPE"] = "filesystem"  # Stores sessions on the server
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
Session(app)  # Initialize Flask-Session

# Initialize OAuth
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=OAUTH_CLIENT_ID,
    client_secret=OAUTH_CLIENT_SECRET,
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
)

# Allowed emails list
ALLOWED_EMAILS = {"ryanmarks2121@gmail.com"}

@app.route("/")
def home():
    try:
        user = session.get("user", None)

        if not IS_LOCAL and not user:
            return redirect(url_for("login"))

        email = user.get("userinfo", {}).get("email", "Not logged in") if user else "Not logged in"
        print(f"Logged in as: {email}")

        # Restrict data access based on allowed emails
        if email not in ALLOWED_EMAILS:
            print("Unauthorized user attempted access")
            return "Access Denied", 403

        df = pd.read_csv("analyzed_data.csv")
        print(f"Data loaded successfully with columns: {df.columns}")
        data = df.to_dict(orient="records")

        # Scatter data processing
        if "Packet_Length" in df.columns and "Timestamp" in df.columns:
            df["Packet_Length"] = pd.to_numeric(df["Packet_Length"], errors="coerce")
            scatter_data = df[df["Anomaly"] == "Anomaly"][["Packet_Length", "Timestamp"]].dropna()
            scatter_data["Timestamp"] = pd.to_datetime(scatter_data["Timestamp"]).apply(lambda x: x.timestamp() * 1000)
            scatter_data_json = scatter_data.to_dict(orient="records") if not scatter_data.empty else []
            print(f"Scatter data prepared with {len(scatter_data)} anomalies")
        else:
            scatter_data_json = []
            print("No 'Packet_Length' or 'Timestamp' columns found.")

        return render_template("index.html", columns=df.columns, data=data, scatter_data=scatter_data_json, email=email, is_render=not IS_LOCAL)

    except Exception as e:
        print(f"Error loading data: {e}")
        return "Error loading data", 500

@app.route("/login")
def login():
    if not IS_LOCAL:
        state = os.urandom(16).hex()
        session["oauth_state"] = state
        redirect_uri = request.url_root + "authorize"

        print(f"Generated OAuth state: {state}")
        print(f"Redirecting to Google OAuth with URI: {redirect_uri}")

        return google.authorize_redirect(redirect_uri, state=state)
    else:
        return redirect(url_for("home"))

@app.route("/authorize")
def authorize():
    try:
        print("Attempting to authorize and retrieve the access token")

        expected_state = session.pop("oauth_state", None)
        received_state = request.args.get("state")

        print(f"Expected state: {expected_state}, Received state: {received_state}")

        if expected_state is None or received_state != expected_state:
            raise ValueError("CSRF Warning! State does not match.")

        token = google.authorize_access_token()
        user_info = token.get("userinfo", {})
        email = user_info.get("email")

        if email not in ALLOWED_EMAILS:
            print(f"Unauthorized login attempt by: {email}")
            session.clear()
            return "Access Denied: Unauthorized Email", 403

        session["user"] = token
        print(f"Authorization successful. Logged in as {email}")

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
