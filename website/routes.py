import requests
from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.flask.oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from requests_oauthlib import OAuth2Session
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth


#bp = Blueprint(__name__, 'home')
bp = Blueprint(__name__, 'home')

client_id = 'x5IvGdLTRxTLvWCMHZfC0tWJ'
client_secret = 'VUDZIo14oHOYicsqym5pTSAfdrykFNfyvqShLMvH2zIJv4W2'
authorization_url = 'http://localhost:5000/oauth/authorize'
token_url = 'http://localhost:5000/oauth/token'


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@bp.route('/', methods=('GET', 'POST'))
def home():
    failed = False
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['id'] = user.id
        else:
            failed = True
        password = ''
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients, failed=failed)


@bp.route('/app')
def app():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    global authorization_url
    oauth = OAuth2Session(client_id)
    authorization_url, state = oauth.authorization_url(authorization_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

""" Step 2: User authorization, this happens on the provider. """

@bp.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    oauth = OAuth2Session(client_id, state=session['oauth_state'])
    token = oauth.fetch_token(token_url, client_secret=client_secret,
                               authorization_response=request.url)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['oauth_token'] = token

    return redirect('http://localhost:5000/app/profile')

@bp.route("/app/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    return render_template('client.html')
#    github = OAuth2Session(client_id, token=session['oauth_token'])
#    return jsonify(github.get('https://api.github.com/user').json())


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    elif request.method == 'GET':
        return render_template('register.html')

@bp.route('/logout')
def logout():
    del session['id']
    return redirect('/')


@bp.route('/create_client', methods=['GET', 'POST'])
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')
    client = OAuth2Client(**request.form.to_dict(flat=True))
    client.user_id = user.id
    client.client_id = gen_salt(24)
    if client.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)
    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


@bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)
