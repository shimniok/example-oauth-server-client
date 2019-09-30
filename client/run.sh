#!/bin/sh

. ./env/bin/activate

export FLASK_RUN_PORT=5001
export OAUTHLIB_INSECURE_TRANSPORT=1
export AUTHLIB_INSECURE_TRANSPORT=1
export FLASK_APP=app.py
export FLASK_ENV=development

python -m flask run

exit
