# app.py
from routes import bp
from flask import Flask

app = Flask(__name__)
app.config.update({ 'SECRET_KEY': 'secret' })
app.register_blueprint(bp, url_prefix='')
