#!/bin/sh

echo $0

. ./env/bin/activate

export OAUTHLIB_INSECURE_TRANSPORT=1
export AUTHLIB_INSECURE_TRANSPORT=1
export FLASK_APP=app.py
export FLASK_ENV=development

python -m flask run

exit
