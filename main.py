import requests
import base64
from flask import Flask,request

CLIENT_ID="e0f6f538853641e483980be029e3321a"
CLIENT_SECRET="fd1c0285cd2d4ccc8610a9846f9de172"
local_IPv4="localhost"
client_auth_token=None
user_auth_token=None
user_refresh_token=None
state="abhinav"

def get_user_auth_token(code,redirect_uri):
    headers={'Authorization': 'Basic ' + base64.b64encode((CLIENT_ID+':'+CLIENT_SECRET).encode("ascii")).decode("ascii")}
    payload={
        'grant_type': 'authorization_code',
        'code':code,
        'redirect_uri':redirect_uri
        }
    resp=requests.post("https://accounts.spotify.com/api/token",headers=headers,data=payload)
    print(resp.text)
    if resp.status_code==200:
        global user_auth_token
        global user_refresh_token
        resp=resp.json()
        user_auth_token=resp["access_token"]
        user_refresh_token=resp["refresh_token"]

def get_client_auth_token():
    headers={'Authorization': 'Basic ' + base64.b64encode((CLIENT_ID+':'+CLIENT_SECRET).encode("ascii")).decode("ascii")}
    payload={'grant_type': 'client_credentials'}
    resp=requests.post("https://accounts.spotify.com/api/token",headers=headers,data=payload)
    print(resp.text)
    if resp.status_code==200:
        global client_auth_token
        client_auth_token=resp.json()["access_token"]

def get_recommendations():
    headers={'Authorization': 'Bearer ' + user_auth_token}
    payload={
        "seed_artists":"4NHQUGzhtTLFvgF5SZesLK",
        "seed_genres":"classical,country",
        "seed_tracks":"0c6xIDDpzE81m2q797ordA",
        }
    resp=requests.post("https://api.spotify.com/v1/recommendations",headers=headers,params=payload)
    print(resp.text)

get_client_auth_token()
print(client_auth_token)

app = Flask(__name__)
@app.route('/')
def index():
    return 'Hello world'

@app.route("/authenticate")
def user_auth():
    global state
    scope=None
    redirect_uri=f"http://{local_IPv4}:80/user-auth-callback"
    return app.redirect(f"https://accounts.spotify.com/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={redirect_uri}&state={state}")

@app.route("/user-auth-callback")
def auth_callback():
    global state
    code=request.args.get('code',None)
    state_received=request.args.get('state',None)
    error=request.args.get('error',None)
    if error:
        return error
    elif state==state_received:
        get_user_auth_token(code,f"http://{local_IPv4}:80/user-auth-callback")
    return "authenticated"

app.run(debug=True, port=80, host='0.0.0.0')