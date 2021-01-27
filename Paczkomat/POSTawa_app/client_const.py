import os

OAUTH_BASE_URL = "https://newtenant1234567.us.auth0.com"
OAUTH_ACCESS_TOKEN_URL = OAUTH_BASE_URL + "/oauth/token"
OAUTH_AUTHORIZE_URL = OAUTH_BASE_URL + "/authorize"
OAUTH_CALLBACK_URL = "https://localhost:8080/callback"
OAUTH_CLIENT_ID = "kfnDS6o9JVbAVUZZ7VtSyefGCouIDCbB"
OAUTH_CLIENT_SECRET = os.environ.get("CLIENT_OAUTH_CLIENT_SECRET")
OAUTH_SCOPE = "openid profile"
SECRET_KEY = os.environ.get("CLIENT_AUTH_SECRET")
NICKNAME = "nickname"