import os

OAUTH_BASE_URL = "https://dev-41ytqcw5.us.auth0.com"
OAUTH_ACCESS_TOKEN_URL = OAUTH_BASE_URL + "/oauth/token"
OAUTH_AUTHORIZE_URL = OAUTH_BASE_URL + "/authorize"
OAUTH_CALLBACK_URL = "https://localhost:8083/callback"
OAUTH_CLIENT_ID = "E5lUwI1zM7MIVoC73zDOfZYaBlaOBNpv"
OAUTH_CLIENT_SECRET = os.environ.get("COURIER_OAUTH_CLIENT_SECRET")
OAUTH_SCOPE = "openid profile"
SECRET_KEY = os.environ.get("COURIER_AUTH_SECRET")
NICKNAME = "nickname2"