import os
import time
import requests
import base64
import threading
from flask import Flask, request, render_template
from werkzeug.serving import make_server

local_IPv4 = "https://Recomer.abhinavgeethan.repl.co"

class AmazonConnection():

  def __init__(self):
    self.base_url = 'https://api.music.amazon.dev'
    self.device_auth_url = 'https://api.amazon.com/auth/o2/create/codepair'
    self.token_request_url = 'https://api.amazon.com/auth/o2/token'
    self.AMZN_CLIENT_ID = os.environ['AMZN_CLIENT_ID']
    self.user_code = None
    self.device_code = None
    self.verification_uri = None
    self.interval = None
    self.expires_in = None
    self.timer_starttime = None
    self.access_token = None
    self.refresh_token = None

  def get_auth_codes(self):
    payload = {
      'response_type': 'device_code',
      'client_id': self.AMZN_CLIENT_ID,
      'scope': 'profile profile:user_id'
    }
    resp = requests.post(self.device_auth_url, data=payload)
    if resp.status_code == 200:
      resp = resp.json()
      self.user_code = resp["user_code"]
      self.device_code = resp["device_code"]
      self.verification_uri = resp["verification_uri"]
      self.interval = resp['interval']
      self.expires_in = resp['expires_in']
      self.timer_starttime = time.time()
      print(self.verification_uri, self.user_code)
    else:
      print(resp)
      raise Exception("Code Request Failed")

  def get_user_access_code(self):
    payload = {
      'grant_type': 'device_code',
      'device_code': self.device_code,
      'user_code': self.user_code
    }
    resp = requests.post(self.token_request_url, data=payload)
    if resp.status_code == 200:
      resp = resp.json()
      self.access_token = resp["access_token"]
      self.refresh_token = resp["refresh_token"]
      return {'status': 'authenticated'}
    else:
      error = resp.json()['error']
      if error == 'authorization_pending':
        return {'status': 'pending'}
      else:
        raise Exception("Authentication Failed")

  def login(self):
    self.get_auth_codes()
    print("Visit URL to Login")
    while ((time.time() - self.timer_starttime) < self.expires_in):
      print("Amazon: Waiting for Authentication", end="\r")
      last_poll_time = time.time_ns()
      status = self.get_user_access_code()['status']
      if status != 'pending':
        print(status)
        break
      if (time.time_ns() - last_poll_time) < self.interval:
        time.sleep((time.time_ns() - last_poll_time) * 0.000000001)
    print()
    print('Exited')


class SpotifyConnection():

  def __init__(self):
    self.CLIENT_ID = os.environ['CLIENT_ID']
    self.CLIENT_SECRET = os.environ['CLIENT_SECRET']
    self.client_auth_token = None
    self.user_auth_token = None
    self.user_refresh_token = None
    self.state = "abhinav"

  def get_user_auth_token(self, code, redirect_uri):
    headers = {
      'Authorization':
      'Basic ' + base64.b64encode(
        (self.CLIENT_ID + ':' +
         self.CLIENT_SECRET).encode("ascii")).decode("ascii")
    }
    payload = {
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': redirect_uri
    }
    resp = requests.post("https://accounts.spotify.com/api/token",
                         headers=headers,
                         data=payload)
    if resp.status_code == 200:
      resp = resp.json()
      self.user_auth_token = resp["access_token"]
      self.user_refresh_token = resp["refresh_token"]
      return self.user_auth_token
    else:
      raise Exception("Authentication Failed")

  def get_client_auth_token(self):
    headers = {
      'Authorization':
      'Basic ' + base64.b64encode(
        (self.CLIENT_ID + ':' +
         self.CLIENT_SECRET).encode("ascii")).decode("ascii")
    }
    payload = {'grant_type': 'client_credentials'}
    resp = requests.post("https://accounts.spotify.com/api/token",
                         headers=headers,
                         data=payload)
    if resp.status_code == 200:
      self.client_auth_token = resp.json()["access_token"]
    else:
      raise Exception("Server Authentication Failed")


class ServerThread(threading.Thread):

  def __init__(self, app):
    threading.Thread.__init__(self)
    self.server = make_server(host='0.0.0.0', port=80, app=app)
    self.ctx = app.app_context()
    self.ctx.push()

  def run(self):
    print('Starting Server')
    self.server.serve_forever()

  def shutdown(self):
    self.server.shutdown()


def get_recommendations():
  headers = {'Authorization': 'Bearer ' + user_auth_token}
  payload = {
    "seed_artists": "4NHQUGzhtTLFvgF5SZesLK",
    "seed_genres": "classical,country",
    "seed_tracks": "0c6xIDDpzE81m2q797ordA",
  }
  resp = requests.post("https://api.spotify.com/v1/recommendations",
                       headers=headers,
                       params=payload)
  print(resp.text)


def start_server():
  global server
  app = Flask("Recomer_Auth")
  # App routes defined here
  @app.route('/')
  def index():
    return 'Hello world'

  @app.route('/privacy')
  def show_policy():
    return render_template('amzn_privacy.html')

  @app.route("/authenticate")
  def spotify_user_auth():
    global spotify
    spotify_redirect_uri = f"{local_IPv4}/spotify-user-auth-callback"
    return app.redirect(
      f"https://accounts.spotify.com/authorize?response_type=code&client_id={spotify.CLIENT_ID}&redirect_uri={spotify_redirect_uri}&state={spotify.state}"
    )

  @app.route("/spotify-user-auth-callback")
  def spotify_auth_callback():
    global spotify
    code = request.args.get('code', None)
    state_received = request.args.get('state', None)
    error = request.args.get('error', None)
    if error:
      return error
    elif spotify.state == state_received:
      spotify.get_user_auth_token(code,
                                  f"{local_IPv4}/spotify-user-auth-callback")
    return "authenticated"

  server = ServerThread(app)
  server.start()
  print('Server started')


def stop_server():
  global server
  server.shutdown()


spotify = SpotifyConnection()
spotify.get_client_auth_token()
print(spotify.client_auth_token)
amazon = AmazonConnection()
amzn_login = threading.Thread(target=amazon.login())
start_server()
while spotify.user_auth_token == None:
  print("Spotify: Waiting for Authentication", end="\r")
  time.sleep(5)
print("Authenticated")
stop_server()
amzn_login.join()
