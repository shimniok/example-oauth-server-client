import base64
import requests
from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
from requests_oauthlib import OAuth2Session

bp = Blueprint(__name__, 'home')

client_id = 'x5IvGdLTRxTLvWCMHZfC0tWJ'
client_secret = 'VUDZIo14oHOYicsqym5pTSAfdrykFNfyvqShLMvH2zIJv4W2'
redirect_url = 'http://localhost:5000/profile'
api_url = 'http://localhost:5000/api/me'
authorization_url = 'http://localhost:5000/oauth/authorize'
token_url = 'http://localhost:5000/oauth/token'

@bp.route('/')
def app():
    return render_template('home.html')

@bp.route("/callback", methods=["GET"])
def callback():
    """
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    oauth = OAuth2Session(client_id, state=session['oauth_state'])
    token = oauth.fetch_token(token_url, client_secret=client_secret,
                               authorization_response=request.url)

    # Persist the token and go back to original page
    session['oauth_token'] = token
    return redirect('/profile')

@bp.route("/profile", methods=["GET"])
def profile():
    """
    Fetch a protected resource using an OAuth 2 token, if one exists.
    """
    try:
        token = session['oauth_token']
    except:
        """
        If token not available, initiate oauth2 request for authorization_url
        """
        global authorization_url
        oauth = OAuth2Session(client_id, scope=['profile'])
        authorization_url, state = oauth.authorization_url(authorization_url)

        # State is used to prevent CSRF, keep this for later.
        session['oauth_state'] = state
        return redirect(authorization_url)

    if token:
        oauth_session = OAuth2Session(client_id, token=token)
#        response = oauth_session.get(api_url)
#        return response.text

        response = requests.get(
            api_url,
            headers={ 'Authorization': 'Bearer '+token['access_token']}
        )

        json = response.json()
        username = json['username']
        id = json['id']
        return render_template('profile.html', username=username, id=id)
